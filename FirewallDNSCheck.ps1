<#
    .DESCRIPTION
        Script pulls Firewall Log from Local Workstation, Compares to your Local DNS.
        Looking for Rogue Computers in your environment.
        Only effective with a local DNS Server and all known devices are registered. Will identify devices NOT in DNS. 

    .OUTPUTS
        Report found under $logPath below, default is c:\COD-Logs\COMPUTERNAME\DATETIME\$OutputFile
    
    .EXAMPLE
        Option 1
        1. Command Prompt (Admin) "powershell -Executionpolicy Bypass -File PATH\FILENAME.ps1"

    .NOTES
        Author Perk
        Last Update 12/31/21
    
        Powershell 5.1 or higher
        Run as Administrator
    
    .FUNCTIONALITY
        PowerShell Language
        Active Directory
    
    .Link
    https://github.com/COD-Team
    YouTube Channel with this Video https://www.youtube.com/channel/UCWtXSYvBXU6YqzqBqNcH_Kw

    Thanks to Twan van Beers - Across my Lab I noticed that two computers were not functioning as intented
    All the firewall settings were in place, but there were no logs. 
    https://neroblanco.co.uk/2017/03/windows-firewall-not-writing-logfiles/

    Thanks to Martin Norlunn for the Class
    https://www.powershellgallery.com/packages/Get-WindowsFwLog/1.0/Content/Get-WindowsFwLog.ps1
#>

$ComputerName = $env:COMPUTERNAME
$logpath = "C:\COD-Logs\$ComputerName\$(get-date -format "yyyyMMdd-hhmmss")"
#$logpath = "\\SERVERNAME\SHARENAME\COD-Logs\$ComputerName\$(get-date -format "yyyyMMdd-hhmmss")"
    If(!(test-path $logpath))
    {
          New-Item -ItemType Directory -Force -Path $logpath | Out-Null
    }

$FirewallLogFile = 'C:\Windows\system32\LogFiles\Firewall\pfirewall.log'
$OutputFile = "$logpath\Firewall-DNS.log"

$DNSServer = @('172.16.32.201','172.16.33.31')
#$DNSServer = "172.16.32.201"
$JobSleep = 2

## End of Variables

class WindowsFwLogEntry
{
    [datetime]$DateTime
    [string]$Action
    [string]$Protocol
    [ipaddress]$SourceIP
    [ipaddress]$DestinationIP
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

# Reads the Firewall Log - Due to size of logs, you might use the -First XXX to limit data returning for testing
Write-Host -ForegroundColor Yellow "Reading Firewall Log $FirewallLogFile, Please be Patient"
$LogEntries = Get-Content -Path $FirewallLogFile | Select-Object -Skip 5 #-first 100

# Parse Firewall Log into usable data
Write-Host -ForegroundColor Yellow "Parsing IP Addresses"
$LogEntries = $LogEntries | ForEach-Object {
    Try {[WindowsFwLogEntry]::new($_)}
    Catch {}
}

Write-Host -ForegroundColor Yellow "Creating Source IP List"
$SourceIP = $LogEntries | Select-Object SourceIP, Action -Unique | Sort-Object SourceIP | Where-Object Action -eq Drop

$ScriptBlock = 
{
    Try 
    {
        Resolve-DnsName -Name $args[0] -Server $using:DNSServer -ErrorAction Stop
    }
    Catch
    {
        Write-Output "$args.IPAddresstoString Not Found"
    }
}

Write-Host -ForegroundColor Yellow "Starting Jobs"
foreach ($ip in $SourceIP.sourceip)
{
    Start-Job -ArgumentList $ip -ScriptBlock $ScriptBlock
}

$UncompletedJobs = Get-Job | Where-Object {$_.State -ne "Completed"}
    Do {
        $JobProgress = Get-Job | Where-Object {$_.State -ne "Completed"} | Measure-Object | Select-Object -ExpandProperty Count
        Write-Host -ForegroundColor Yellow "Waiting for $JobProgress jobs to complete"
        $UncompletedJobs = Get-Job | Where-Object {$_.State -ne "Completed"}
        Start-Sleep $JobSleep
        }
    Until ($null -eq $UncompletedJobs)

$CompletedJobs = Get-Job | Where-Object {$_.State -eq "Completed"}
    ForEach ($Job in $CompletedJobs)
    {
        Receive-Job -id $Job.id | out-file -Append $OutputFile
        Remove-Job -id $job.Id
    }
Write-Host -ForegroundColor Green "Check $Logpath"

Start-Process Notepad.exe $OutputFile -NoNewWindow