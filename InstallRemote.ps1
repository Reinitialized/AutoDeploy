Start-Transcript -Append "C:\AutoDeploy\Logs\InstallRemote.log"

Write-Output "Checking if we have Administrator rights ..."
# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Output "Lacking Administrator permissions, attempting to elevate. If UAC pops up, please click Yes, otherwise AutoDeploy will terminate."
    $CommandLine = "-ExecutionPolicy Bypass -File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
    Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
    Exit
}

Write-Output "Downloading Setup.ps1"
Invoke-WebRequest "https://raw.githubusercontent.com/Reinitialized/AutoDeploy/indev/Setup.ps1" -OutFile C:\AutoDeploy\Setup.ps1

Write-Output "Moving dependencies to correct locations"
Move-Item "$PSScriptRoot\Applications" C:\AutoDeploy\Applications -Force

Write-Output "Validating Local Device Administrator"
$LocalAccount = Get-LocalUser -Name "simpatico" -ErrorAction SilentlyContinue
if (-not $LocalAccount) {
    Write-Output "Couldn't find Local Device Administrator, creating one"
    New-LocalUser -Name "simpatico" -NoPassword
}
Set-LocalUser -Name "simpatico" -FullName "Simpatico Systems, LLC" -Description "Local Device Administrator" -Password (ConvertTo-SecureString -String "2Rbsx931nKXKye2D" -AsPlainText -Force)
Set-LocalUser -Name "simpatico" -AccountNeverExpires -PasswordNeverExpires:$false

Write-Output "Starting Setup.ps1"
Start-Process -FilePath PowerShell.exe -ArgumentList "-ExecutionPolicy Bypass -File C:\AutoDeploy\Setup.ps1"