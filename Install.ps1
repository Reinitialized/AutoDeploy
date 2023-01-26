Start-Transaction -Append "C:\AutoDeploy\Logs\Install.log"

Write-Debug "Configuring Local Device Administrator"
$LocalUser = New-LocalUser -Name "simpatico" -FullName "Simpatico Systems, LLC" -Description "Local Device Administrator" -NoPassword -PasswordNeverExpires $true -AccountNeverExpires $true
Add-LocalGroupMember -Group (Get-LocalGroup -Name "Administrators") -Member $LocalUser

New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -PropertyType String -Name AutoAdminLogin -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -PropertyType String -Name DefaultDomainName -Value . -Force
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -PropertyType String -Name DefaultUserName "simpatico" -Force
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -PropertyType String -Name DefaultPassword "simpatico" -Force

Write-Debug "Setting AutoDeploy to run on first login"
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -PropertyType String -Name "AutoDeploy" -Value "PowerShell -ExecutionPolicy Bypass -File C:\AutoDeploy\Setup.ps1" -Force

Write-Debug "Disable OOBE Privacy Settings prompt"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -PropertyType DWORD -Value 1 -Force

Write-Debug "AutoDeploy install complete"
Stop-Transcript