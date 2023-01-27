Start-Transaction -Append "C:\AutoDeploy\Logs\Install.log"

Write-Debug "Checking for Internet access"
if (-Not (Test-Connection 1.1.1.1 -Quiet -Count 1 -ErrorAction SilentlyContinue)) {
    Write-Debug "Internet access not available, checking for Ethernet drivers"
    if ((Get-NetAdapter | Where-Object {$_.DriverDescription -match "Ethernet"})) {
		Throw "Cannot continue: Ethernet drivers were detected, but could not access the Internet.`nPlease perform the following checks and try again:`n- Verify an Ethernet cable is connected to the computer`n- Verify the LAN is functional"
	}
    
    Write-Debug "Attempting to install drivers"
    $USBDrive = Get-WmiObject Win32_LogicalDisk -Filter "DriveType = 2" | Where-Object { $_.VolumeName -eq "AutoDeployUSB" }
    if (-Not $USBDrive) {
        Throw "Cannot continue: Unable to locate AutoDeploy USB, a required dependency. Please try again."
    }
    Start-Process -NoNewWindow -Wait "$($USBDrive.DeviceId)\AutoDeploy\Applications\SnappyDriver\SDIO.exe" -ArgumentList "-nogui -license -nologfile -nosnapshot -autoinstall -autoclose"

    Write-Debug "Sleeping for 15 seconds to let drivers settle"
    Start-Sleep 15

    Write-Debug "Checking for Internet access again"
    if (-Not (Test-Connection 1.1.1.1 -Quiet -Count 1 -ErrorAction SilentlyContinue)) {
        Write-Debug "Checking to see if Ethernet drivers installed"
        if (-Not (Get-NetAdapter | Where-Object {$_.DriverDescription -match "Ethernet"})) {
            Throw "Cannot continue: No Ethernet drivers were installed. AutoDeploy may not have the required drivers or is not compatible with this computer."
        } else {
            Throw "Cannot continue: Ethernet drivers were detected, but could not access the Internet.`nPlease perform the following checks and try again:`n- Verify an Ethernet cable is connected to the computer`n- Verify the LAN is functional"
        }
    }
}

Write-Debug "Downloading Setup.ps1"
Invoke-WebRequest "https://raw.githubusercontent.com/Reinitialized/AutoDeploy/indev/Setup.ps1" -OutFile C:\AutoDeploy\Setup.ps1

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