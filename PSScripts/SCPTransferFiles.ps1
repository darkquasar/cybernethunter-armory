<#

Transfer Files with Powershell using WinSCP libraries by Dennis S.

#>


[Reflection.Assembly]::LoadFrom(“C:\temp\WinSCPnet.dll”) | Out-Null

$sessionOptions = New-Object WinSCP.SessionOptions
$sessionOptions.Protocol = [WinSCP.Protocol]::Sftp
$sessionOptions.HostName = "192.168.250.138"
$sessionOptions.UserName = "remnux"
$sessionOptions.Password = "malware"
$sessionOptions.GiveUpSecurityAndAcceptAnySshHostKey = $true
$session = New-Object WinSCP.Session
$session.Open($sessionOptions)
$transferOptions = New-Object WinSCP.TransferOptions
$transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
$SourcePath = "$filename"
$DestinationPath = "home/remnux"
$session.PutFiles("$SourcePath", "$DestinationPath", $False, $transferOptions)
$session.Close()
