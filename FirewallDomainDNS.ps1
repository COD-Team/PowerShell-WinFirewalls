<#
    .DESCRIPTION
        Script Attempts to communicate with Active Directory and all Windows Computers in the Domain
        Pull SourceIPs from all computers in the domain, compares to Local DNS Server to identify rogue devices in network. 

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

$Tasks = @(
    ,"GetFirewallLog"
    ,"GetFirewallContent"
    ,"LaunchNotepad"
    )

# If you are not an Administrator, Script will Exit
#Requires -RunAsAdministrator

# If you are not on Powershell version 5.1 or higher, Script will Exit
$versionMinimum = [Version]'5.1.000.000'
    if ($versionMinimum -gt $PSVersionTable.PSVersion)
    { throw "This script requires PowerShell $versionMinimum" }

# If your computer is NOT on a Domain, Script will exit - Checkout Standalone.ps1 for non-domain computers
if ($env:computername  -eq $env:userdomain) 
    {
        Write-Host -fore red "$env:ComputerName is not joined to a Domain, Script Exiting" 
        Exit
    }

# Get Domain Name, Creates a DomainName Folder to Store Reports
# Added 1/7/21 Powershell 7.2.1 Compatibility Get-WmiObject not compatible with Powershell 7.2.1
#$DomainName = (Get-WmiObject win32_computersystem).domain
$DomainName = (Get-CimInstance Win32_ComputerSystem).Domain


# Get Computer Name
$ComputerName = $env:computername

#Path where the results will be written, suggest network share for best results. 
#$logpath = "C:\COD-Logs\$DomainName\$(get-date -format "yyyyMMdd-hhmmss")"
$logpath = "\\DC2016\SHARES\COD-Logs\$DomainName\$(get-date -format "yyyyMMdd-hhmmss")"
    If(!(test-path $logpath))
    {
          New-Item -ItemType Directory -Force -Path $logpath
    }
#Counter for Write-Progress
$Counter = 0

# Added 1/7/21 PowerShell 7.2.1 Compatibility for Out-File not printing escape characters
if ($PSVersionTable.PSVersion.major -ge 7) {$PSStyle.OutputRendering = 'PlainText'}

# Logfile where all the results are dumped
$OutputFile = "$logpath\Firewall.log"

$FirewallLogFile = 'C:\Windows\system32\LogFiles\Firewall\pfirewall.log'
$DNSServer = @('172.16.32.201','172.16.33.31')
#$DNSServer = "172.16.32.201"
$JobSleep = 2

#Sets Header information for the Reports
Write-Output "[INFO] Running $PSCommandPath" | Out-File -Append $OutputFile
Write-Output (Get-Date) | Out-File -Append $OutputFile
Write-Output "POWERSHELL COD ASSESSMENT SCRIPT RESULTS" | Out-File -Append $OutputFile
Write-Output "Executed Script from $ComputerName on Domain $DomainName" | Out-File -Append $OutputFile
Write-Output "------------------------------------------------------------------------------------------------------------------------" | Out-File -Append $OutputFile

#$DomainControllers = (Get-ADDomainController | Select-Object Name)
$DomainControllers = (Get-ADForest).Domains | ForEach-Object {Get-ADDomain -Identity $_ | Select-Object -ExpandProperty ReplicaDirectoryServers}

# Return all Windows Computers from Active Directory - Select 1 of the 2 options
$DomainComputers = Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -Properties Name, OperatingSystem | Select-Object Name, OperatingSystem 

# Randomly scan a set number of computers in the domain
#$DomainComputers = Get-Random -count 2 (Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -Properties Name, OperatingSystem | Select-Object Name, OperatingSystem)

# This section tests all computers in $DomainComputers Array for Accessibility (Online/Offline) Produces $Online Array, saves time only executing with computers online
$GetOnline = Invoke-command –ComputerName $DomainComputers.Name -ErrorAction SilentlyContinue –scriptblock {[pscustomobject]@{ result = (Get-Service -name "winRM").count}}
    
    $Online =  $GetOnline | Select-Object -ExpandProperty PSComputerName | Sort-Object PSComputerName
    $Offline = Compare-Object -ReferenceObject $DomainComputers.Name -DifferenceObject $Online | Select-Object -ExpandProperty InputObject 

# Display to Screen all Domain Controllers
    if ((Get-ADDomainController -filter * | Select-Object name | Measure-Object | Select-Object Count).count -ge 1) {
        Write-Host -fore Cyan 'Domain Controllers' -Separator "`n" 
        Write-Host -fore Cyan '-----------------' -Separator "`n"
        Write-Host -fore Cyan $DomainControllers -Separator "`n" 
        Write-Host '' -Separator "`n"
    }
# Display to Screen all Computers not Accessible 
    if ($Offline -ge 1) {
        Write-Host -fore red 'Computers Offline' -Separator "`n" 
        Write-Host -fore red '-----------------' -Separator "`n" 
        Write-Host -fore red $Offline -Separator "`n" 
        Write-Host -fore red '' -Separator "`n"
    }
# Display to Screen all Computers Accessible, Script will execute functions on all computers listed
    if ($Online -ge 1) {
        Write-Host -fore green 'Computers Online' -Separator "`n" 
        Write-Host -fore green '-----------------' -Separator "`n"
        Write-Host -fore green $online -Separator "`n" 
    }

#Write to File
    if ((Get-ADDomainController -filter * | Select-Object name | Measure-Object | Select-Object Count).count -ge 1) {
        Write-Output 'Domain Controllers' | Out-File -Append $OutputFile
        Write-Output '-----------------' | Out-File -Append $OutputFile
        $DomainControllers | Out-File -Append $OutputFile
        Write-Output '' | Out-File -Append $OutputFile
    }
    if ($Offline -ge 1) {
        Write-Output 'Computers Offline' | Out-File -Append $OutputFile
        Write-Output '-----------------' | Out-File -Append $OutputFile
        $Offline | Out-File -Append $OutputFile
        Write-Output '' | Out-File -Append $OutputFile
    }
    if ($Online -ge 1) {
        Write-Output 'Computers Online' | Out-File -Append $OutputFile
        Write-Output '-----------------' | Out-File -Append $OutputFile
        $Online | Out-File -Append $OutputFile
    }


###################################################################################################################################################################
Function GetFirewallLog
{
    Write-Output "Does Firewall Log Path Exist?" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ScriptBlock {
        If (Test-Path $Using:FirewallLogFile)
        {
            Write-Output "$env:ComputerName True"
        }
        Else 
        {
            Write-Output "$env:ComputerName False"
        }
    }
    $Results | Out-File -Append $OutputFile    
}
#####################################################################################################
Function GetFirewallContent
{
    Write-Output "Unique SourceIP Addresses with DNS Response" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ScriptBlock {

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
            $LogEntries = Get-Content -path $Using:FirewallLogFile | Select-Object -Skip 5 #-first 10            
            $LogEntries = $LogEntries | ForEach-Object {
                Try {[WindowsFwLogEntry]::new($_)}
                Catch {}
            }
           
            $LogEntries | Select-Object SourceIP, Action | Where-Object Action -eq Drop
    }

    $SourceIP = $Results | Select-Object SourceIP -Unique

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
        $Jobs1 = Start-Job -ArgumentList $ip -ScriptBlock $ScriptBlock
        Write-Host -ForegroundColor yellow "Starting Job" $Jobs1.ID
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

}

#####################################################################################################
Function LaunchNotepad 
{
    Start-Process Notepad.exe $OutputFile -NoNewWindow
}

Foreach ($Task in $Tasks)
{
    #Write-Progress -Activity "Collecting Assessment Data" -Status "In progress: $Task" -PercentComplete (($Counter / $Tasks.count) * 100)     
    Add-Content -Path $OutputFile -Value "------------------------------------------------------------------------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value "####################################### Running Function $Task #######################################"
    Add-Content -Path $OutputFile -Value "------------------------------------------------------------------------------------------------------------------------"
    &$Task
    $Counter ++    
}

Add-Content -Path $OutputFile -Value (Get-Date)
Write-Host " "
Write-Host -fore green "Results saved to: $OutputFile" 
write-Host -fore green "Script Completed"
