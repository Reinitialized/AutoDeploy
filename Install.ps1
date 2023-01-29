Start-Transcript -Append "C:\AutoDeploy\Logs\Install.log"

$USBDrive = Get-WmiObject Win32_LogicalDisk -Filter "DriveType = 2" | Where-Object { $_.VolumeName -eq "AutoDeployUSB" }
if (-Not $USBDrive) {
    Throw "Cannot continue: Unable to locate AutoDeploy USB, a required dependency. Please try again."
}

Write-Output "Checking for Internet access"
if (-Not (Test-Connection 1.1.1.1 -Quiet -Count 1 -ErrorAction SilentlyContinue)) {
    Write-Output "Internet access not available, checking for Ethernet drivers"
    if ((Get-NetAdapter | Where-Object {$_.DriverDescription -match "Ethernet"})) {
		Throw "Cannot continue: Ethernet drivers were detected, but could not access the Internet.`nPlease perform the following checks and try again:`n- Verify an Ethernet cable is connected to the computer`n- Verify the LAN is functional"
	}
    
    Write-Output "Attempting to install drivers"
    Start-Process -NoNewWindow -Wait "C:\AutoDeploy\Applications\SnappyDriver\SDIO.exe" -ArgumentList "-nogui -license -nologfile -nosnapshot -autoinstall -autoclose"

    Write-Output "Sleeping for 15 seconds to let drivers settle"
    Start-Sleep 15

    Write-Output "Checking for Internet access again"
    if (-Not (Test-Connection 1.1.1.1 -Quiet -Count 1 -ErrorAction SilentlyContinue)) {
        Write-Output "Checking to see if Ethernet drivers installed"
        if (-Not (Get-NetAdapter | Where-Object {$_.DriverDescription -match "Ethernet"})) {
            Throw "Cannot continue: No Ethernet drivers were installed. AutoDeploy may not have the required drivers or is not compatible with this computer."
        } else {
            Throw "Cannot continue: Ethernet drivers were detected, but could not access the Internet.`nPlease perform the following checks and try again:`n- Verify an Ethernet cable is connected to the computer`n- Verify the LAN is functional"
        }
    }
}

Copy-Item -Path "$($USBDrive.DeviceId)\AutoDeploy\Applications" -Destination "C:\AutoDeploy\Applications" -Recurse -Confirm:$false

Write-Output "Downloading Setup.ps1"
Invoke-WebRequest "https://raw.githubusercontent.com/Reinitialized/AutoDeploy/indev/Setup.ps1" -OutFile C:\AutoDeploy\Setup.ps1

Write-Output "Configuring Local Device Administrator"
$LocalUser = New-LocalUser -Name "simpatico" -FullName "Simpatico Systems, LLC" -Description "Local Device Administrator" -Password (ConvertTo-SecureString -String "2Rbsx931nKXKye2D" -AsPlainText -Force)
Set-LocalUser -Name "simpatico" -AccountNeverExpires -PasswordNeverExpires
Add-LocalGroupMember -Group (Get-LocalGroup -Name "Administrators") -Member $LocalUser

New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -PropertyType String -Name AutoAdminLogin -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -PropertyType String -Name DefaultDomainName -Value . -Force
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -PropertyType String -Name DefaultUserName -Value "simpatico" -Force
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -PropertyType String -Name DefaultPassword -Value "2Rbsx931nKXKye2D" -Force

Write-Output "Setting AutoDeploy to run on first login"
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -PropertyType String -Name "AutoDeploy" -Value "PowerShell -ExecutionPolicy Bypass -File C:\AutoDeploy\Setup.ps1" -Force

Write-Output "Disable OOBE Privacy Settings prompt"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -PropertyType DWORD -Name DisablePrivacyExperience -Value 1 -Force

Write-Output "AutoDeploy install complete"
Stop-Transcript