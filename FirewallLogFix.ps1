<#
    Thanks to Twan van Beers - Across my Lab I noticed that two computers were not functioning as intented
    All the firewall settings were in place, but there were no logs. 
    https://neroblanco.co.uk/2017/03/windows-firewall-not-writing-logfiles/
#>
Function New-FirewallLogFile
{
  param ([string]$filename)

  New-Item $FileName -Type File -Force
  $Acl = Get-Acl $FileName
  $Acl.SetAccessRuleProtection( $True, $False )
  $PermittedUsers = @( 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc' )
  foreach( $PermittedUser in $PermittedUsers ) {
    $Permission = $PermittedUser, 'FullControl', 'Allow'
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $Permission
    $Acl.AddAccessRule( $AccessRule )
  }
 
  $Acl.SetOwner( (new-object System.Security.Principal.NTAccount( 'BUILTIN\Administrators' )) )

  $Acl | Set-Acl $FileName 
}

New-FirewallLogFile 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log'
New-FirewallLogFile 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log.old'
# Make Sure to Reboot