<#
    .DESCRIPTION
        Script Attempts to communicate with Active Directory and all Windows Computers in the Domain
        Reads each Computer Firewall Log, provides reports for on Firewall Entries

    .PARAMETER NAME
        No Parameters, but control Functions by commenting or uncommenting Functions under $TASKS (See example Task/Function)

    .OUTPUTS
        Report found under $logPath below, Setup Networkshare for \\SERVERNAME\SHARE\COD-Logs\DOMAINNAME\DATETIME
    
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

$Tasks = @(
    #,"Example"
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
$DomainName = (Get-WmiObject win32_computersystem).domain

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

# Logfile where all the results are dumped
$OutputFile = "$logpath\Firewall.log"

#Sets Header information for the Reports
Write-Output "[INFO] Running $PSCommandPath" | Out-File -Append $OutputFile
Write-Output (Get-Date) | Out-File -Append $OutputFile
Write-Output "POWERSHELL COD ASSESSMENT SCRIPT RESULTS" | Out-File -Append $OutputFile
Write-Output "Executed Script from $ComputerName on Domain $DomainName" | Out-File -Append $OutputFile
Write-Output "------------------------------------------------------------------------------------------------------------------------" | Out-File -Append $OutputFile


#$DomainControllers = (Get-ADDomainController | Select-Object Name)
$DomainControllers = (Get-ADForest).Domains | ForEach-Object {Get-ADDomain -Identity $_ | Select-Object -ExpandProperty ReplicaDirectoryServers}

# Return all Windows Computers from Active Directory - Select 1 of the 3 options
$DomainComputers = Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -Properties Name, OperatingSystem | Select-Object Name, OperatingSystem 

# Only Scan computers listed in Array
#$DomainComputers = ('Workstation-3')

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

$FirewallLogFile = 'C:\Windows\system32\LogFiles\Firewall\pfirewall.log'

###################################################################################################################################################################
Function GetFirewallLog
{
    Write-Output "Does Firewall Path Exist?" | out-file -Append $OutputFile
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
    Write-Output "Unique Source IP Addresses?" | out-file -Append $OutputFile
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
            $LogEntries = Get-Content -path $Using:FirewallLogFile | Select-Object -Skip 5 #-first 1000
            # Parse Firewall Log into usable data
            
            $LogEntries = $LogEntries | ForEach-Object {
                Try {[WindowsFwLogEntry]::new($_)}
                Catch {}
            }
           
            # 1. Returns Counts by Protocol - Match Results
            $LogEntries | Select-Object Protocol, DestinationPort, Action | Where-Object Action -eq Drop | Group-Object Protocol, Destinationport, Action | Select-Object Count, Name

            # 2. Returns Unique IP Address
            #$LogEntries | Select-Object SourceIP, Action | Where-Object Action -eq Drop
    }
    # 1. Returns Counts by Protocol - Match Results
    $Results | Select-Object PSComputerName, Count, Name | Out-File -Append $OutputFile  

    # 2. Returns Unique IP Address
    #$Results | Select-Object SourceIP -Unique | Out-File -Append $OutputFile
    #$Results | Select-Object SourceIP -Unique | Out-File -Append $Logpath\SourceIP.txt
    #$Results | Select-Object SourceIP -Unique | Export-CSV $Logpath\SourceIP.CSV -NoTypeInformation
}

#####################################################################################################
Function LaunchNotepad 
{
    Start-Process Notepad.exe $OutputFile -NoNewWindow
}

Foreach ($Task in $Tasks)
{
    Write-Progress -Activity "Collecting Assessment Data" -Status "In progress: $Task" -PercentComplete (($Counter / $Tasks.count) * 100)     
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