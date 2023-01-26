Start-Transaction -Append "C:\AutoDeploy\Logs\Setup.log"
Write-Output "AutoDeploy started. Waiting 60 seconds to let Windows settle"
Start-Sleep -Seconds 60

Write-Debug "Checking for AutoDeploy USB drive"
$USBDrive = Get-WmiObject Win32_LogicalDisk -Filter "DriveType = 2" | Where-Object { $_.VolumeName -eq "AutoDeployUSB" }
if (-Not $USBDrive) {
    Write-Error "Cannot continue: Unable to locate AutoDeploy USB, a required dependency. Please try again."
    Throw "Terminating"
}

Write-Debug "Checking for Internet access"
if (-Not (Test-Connection 1.1.1.1 -Quiet -Count 1 -ErrorAction SilentlyContinue)) {
    Write-Debug "Internet access not available, checking for Ethernet drivers"
    if ((Get-NetAdapter | Where-Object {$_.DriverDescription -match "Ethernet"})) {
		Write-Error "Cannot continue: Ethernet drivers were detected, but could not access the Internet.`nPlease perform the following checks and try again:`n- Verify an Ethernet cable is connected to the computer`n- Verify the LAN is functional"
		Throw "Terminating"
	}

    Write-Debug "Attempting to install drivers"
    Start-Process -NoNewWindow -Wait "$($USBDrive.DeviceId)\applications\SnappyDriver\SDIO.exe" -ArgumentList "-nogui -license -nologfile -nosnapshot -autoinstall -autoclose"

    Write-Debug "Sleeping for 15 seconds to let drivers settle"
    Start-Sleep 15

    Write-Debug "Checking for Internet access again"
    if (-Not (Test-Connection 1.1.1.1 -Quiet -Count 1 -ErrorAction SilentlyContinue)) {
        Write-Debug "Checking to see if Ethernet drivers installed"
        if (-Not (Get-NetAdapter | Where-Object {$_.DriverDescription -match "Ethernet"})) {
            Write-Error "Cannot continue: No Ethernet drivers were installed. AutoDeploy may not have the required drivers or is not compatible with this computer."
            Throw "Terminating"
        } else {
            Write-Error "Cannot continue: Ethernet drivers were detected, but could not access the Internet.`nPlease perform the following checks and try again:`n- Verify an Ethernet cable is connected to the computer`n- Verify the LAN is functional"
            Throw "Terminating"
        }
    }
}

Write-Output "[1/x] Configuring Sleep Behavior"
Write-Debug "Disabling Sleep while on AC Power"
powercfg /x /disk-timeout-ac 0
powercfg /x /standby-timeout-ac 0
powercfg /x /hiberate-timeout-ac 0

Write-Debug "Disable Modern Standby and Hiberate instead"
powercfg /setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 2
powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 0
powercfg /setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg /setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 2

Write-Debug "Disabling Fast Start"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -PropertyType DWord -Name HiberbootEnabled -Value 0 -Force

Write-Output "[2/x] Configuring Remote Access"
Write-Debug "Requiring Local Device Administrator to change password on next login"
Set-LocalUser -Name "simpatico" -Password (ConvertTo-SecureString -String "" -AsPlainText -Force)
net user simpatico /logonpasswordchg:yes

Write-Debug "Renaming computer"
switch ($ComputerInfo.PowerPlatformRole) {
    "Mobile"    {
        Rename-Computer -Force ("LT-" + $ComputerInfo.BiosSeralNumber)
        Write-Debug ("Renamed computer to LT-" + $ComputerInfo.BiosSeralNumber)
    } # Typo in Get-ComputerInfo, since we're using built-in PS the fix won't be merged. https://github.com/PowerShell/PowerShell/pull/3167#issuecomment-725418201
    "Desktop"   
    {
        Rename-Computer -Force ("DT-" + $ComputerInfo.BiosSeralNumber)
        Write-Debug ("Renamed computer to DT-" + $ComputerInfo.BiosSeralNumber)
    }
    "Slate"     {
        Rename-Computer -Force ("TB-" + $ComputerInfo.BiosSeralNumber)
        Write-Debug ("Renamed computer to TB-" + $ComputerInfo.BiosSeralNumber)
    }
    default     {
        Rename-Computer -Force $ComputerInfo.BiosSerialNumber
        Write-Debug ("Unknown Platform " + $ComputerInfo.PowerPlatformRole)
    }
}

Write-Debug "Installing NCentral Agent"
Start-Process -NoNewWindow -Wait -FilePath "`"$(USBDrive.DeviceId)\applications\NCentralAgent.exe`"" -ArgumentList "/quiet"

Write-Debug "Waiting for NCentral Agent install to complete ..."
## not the most elegant, but it works
while (!(Get-Process -Name "BASupSrvc" -ErrorAction SilentlyContinue)) {
    Start-Sleep -Seconds 1
}
Write-Debug "NCentral Agent installed, continuing!"

Write-Output "[3/x] Removing bloatware"
$WhitelistedUWPApps = @("MicrosoftWindows.Client.WebExperience", "Microsoft.WindowsStore", "Microsoft.WindowsNotepad", "Microsoft.WindowsCalculator", "Microsoft.WebpImageExtension", "Microsoft.VP9VideoExtensions", "Microsoft.StorePurchaseApp", "Microsoft.SecHealthUI", "Microsoft.ScreenSketch", "Microsoft.HEIFImageExtension", "Microsoft.AV1VideoExtension")
Write-Debug "Removing provisioned UWP bloatware"
foreach ($package in (Get-AppxProvisionedPackage -Online)) {
    if ($WhitelistedUWPApps -notcontains $package.DisplayName) {
        Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction SilentlyContinue
    }
}
Write-Output "Removing installed UWP bloatware"
foreach ($package in Get-AppxPackage) {
    if ($WhitelistedUWPApps -notcontains $package.Name) {
        Start-Process -NoNewWindow -Wait -RedirectStandardOutput "C:\AutoDeploy\Logs\RevoUninstaller.log" -FilePath "$(USBDrive.DeviceId)\RevoUninstaller\x64\RevoUnPro.exe" -ArgumentList "/wa `"$package.Name`""
    }
}

Write-Debug "Removing bloatware capabilities"
$BloatwareCapabilities = @(
    "App.StepsRecorder~~~~0.0.1.0","App.Support.QuickAssist~~~~0.0.1.0","Browser.InternetExplorer~~~~0.0.11.0","MathRecognizer~~~~0.0.1.0","Media.WindowsMediaPlayer~~~~0.0.12.0","Microsoft.Windows.MSPaint~~~~0.0.1.0",
    "Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0","Microsoft.Windows.WordPad~~~~0.0.1.0","OpenSSH.Client~~~~0.0.1.0","Print.Fax.Scan~~~~0.0.1.0","XPS.Viewer~~~~0.0.1.0"
)
foreach ($item in $BloatwareCapabilities) {
    Write-Debug "Removing $item"
    Remove-WindowsCapability -Online -Name $item -ErrorAction SilentlyContinue
}

Write-Debug "Removing Win32 bloatware"
$BlacklistedWin32 = @(
    ## Windows Bloatware
    @{
        Name = "Microsoft 365 - en-us"
        Path = "Microsoft Office"
    },
    @{
        Name = "Microsoft 365 Apps for enterprise"
        Path = "Microsoft Office"
    },
    @{
        Name = "Microsoft 365 Apps for business"
        Path = "Microsoft Office"
    },
    @{
        Name = "Microsoft Edge"
        Path = "Microsoft\Edge\Application"
    },
    ## HP Bloatware
    @{
        Name = "McAfee LiveSafe"
        Path = "McAfee.com"
    },
    @{
        Name = "WebAdvisor by McAfee"
        Path = "McAfee\WebAdvisor"
    },
    @{
        Name = "ExpressVPN"
        Path = "ExpressVPN"
    },
    @{
        Name = "WildTangent Games"
        Path = "WildGames"
    },
    @{
        Name = "Update Installer for WildTangent Games App"
        Path = "WildTangent Games\App"
    },
    @{
        Name = "HP Connection Optimizer"
        Path = "HP Inc.\HP Connection Optimizer"
    },
    @{
        Name = "HP Audio Switch"
        Path = "HP\HPAudioSwitch"
    },
    @{
        Name = "HP Documentation"
        Path = "HP\Documentation"
    }
)

foreach ($programData in $BlacklistedWin32) {
    Write-Debug "Removing $($programData.Name)"
    Start-Process -NoNewWindow -Wait -RedirectStandardOutput "C:\AutoDeploy\Logs\RevoUninstaller.log" -FilePath "$($USBDrive.DeviceId)\applications\RevoUninstaller\x64\RevoUnPro.exe" -ArgumentList "/mu `"$($programData.Name)`" /path `"C:\Program Files (x86)\$($programData.Path)`" /mode Advanced /32"
    Start-Process -NoNewWindow -Wait -RedirectStandardOutput "C:\AutoDeploy\Logs\RevoUninstaller.log" -FilePath "$($USBDrive.DeviceId)\applications\RevoUninstaller\x64\RevoUnPro.exe" -ArgumentList "/mu `"$($programData.Name)`" /path `"C:\Program Files\$($programData.Path)`" /mode Advanced /64"
}

Write-Output "[4/x] Installing WinGet"
$WinGetPackages = @("Microsoft.UI.Xaml.2.7_7.2208.15002.0_x64__8wekyb3d8bbwe.Appx","Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe.Appx","Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe.Appx","Microsoft.DesktopAppInstaller_2022.927.3.0_neutral_~_8wekyb3d8bbwe.Msixbundle")
foreach ($packageName in $WinGetPackages) {
    Add-AppxPackage -Path "$($USBDrive.DeviceId)\$packageName"
}

Write-Output "[5/x] Install applications"

