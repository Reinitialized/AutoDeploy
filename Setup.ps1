Start-Transcript -Append "C:\AutoDeploy\Logs\Setup.log"
Write-Output "AutoDeploy started. Waiting 60 seconds to let Windows settle"
Start-Sleep -Seconds 60

Write-Output "Checking for AutoDeploy USB drive"
$USBDrive = Get-WmiObject Win32_LogicalDisk -Filter "DriveType = 2" | Where-Object { $_.VolumeName -eq "AutoDeployUSB" }
if (-Not $USBDrive) {
    Write-Error "Cannot continue: Unable to locate AutoDeploy USB, a required dependency. Please try again."
    Throw "Terminating"
}

Write-Output "Checking for Internet access"
if (-Not (Test-Connection 1.1.1.1 -Quiet -Count 1 -ErrorAction SilentlyContinue)) {
    Write-Output "Internet access not available, checking for Ethernet drivers"
    if ((Get-NetAdapter | Where-Object {$_.DriverDescription -match "Ethernet"})) {
		Throw "Cannot continue: Ethernet drivers were detected, but could not access the Internet.`nPlease perform the following checks and try again:`n- Verify an Ethernet cable is connected to the computer`n- Verify the LAN is functional"
	} else {
        Throw "Cannot continue: Ethernet drivers could not be detected.`nEither AutoDeploy is missing required drivers or is not compatible with this device."
    }
}

Write-Output "Gathering system facts"
$ComputerInfo = Get-ComputerInfo
$InstalledApps = (Get-WmiObject -Class Win32_Product)

Write-Output "[1/x] Device Configuration"
Write-Output "Configuring System Restore Points"
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5%
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -PropertyType DWord -Name SystemRestorePointCreationFrequency -Value 0 -Force
Enable-ComputerRestore -Drive "$env:SystemDrive"

Write-Output "Setting boot menu to legacy"
bcdedit /set "{current}" bootmenupolicy legacy

Write-Output "Configuring SSD over-provisioning"
fsutil behavior set DisableDeleteNotify 0

Write-Output "Disable Hibernate/Sleep while on AC"
powercfg /x /disk-timeout-ac 0
powercfg /x /standby-timeout-ac 0
powercfg /x /hibernate-timeout-ac 0

Write-Output "Disable Modern Standby and Hibernate instead"
powercfg /setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 2
powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 0
powercfg /setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg /setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 2

Write-Output "Disabling Fast Start"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -PropertyType DWord -Name HiberbootEnabled -Value 0 -Force

Write-Output "Block Windows 11 Upgrade"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -PropertyType DWord -Name TargetReleaseVersion -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -PropertyType String -Name ProductVersion -Value "Windows 10" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -PropertyType String -Name TargetReleaseVersionInfo -Value "22H2" -Force

Write-Output "Disable OOBE after Windows Upgrade"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -PropertyType DWord -Name PrivacyConsentStatus -Value 1 -Force

Write-Output "Disable Microsoft Telemetry"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
Stop-Service "DiagTrack" -WarningAction SilentlyContinue
Set-Service "DiagTrack" -StartupType Disabled
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
    Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled

Write-Output "Disable WiFi Sense"
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

Write-Output "Disable Application suggestions"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
Write-Host  -ForegroundColor Green "Disabling Activity History..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

Write-Output "Disable automatic Microsoft Maps updates"
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

Write-Output "Disabling Windows Feedback"
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

Write-Output "Disable Tailored Experiences"
If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

Write-Output "Restrict Delivery Optimization to LAN only"
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1

Write-Output "Hide People on Taskbar"
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

Write-Output "Disable `"News and Interest`""
If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2

Write-Output "Hide `"Meet Now`" from Taskbar"
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1

Write-Output "Default Windows Explorer to `"This PC`""
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

Write-Output "Hide 3D Objects from `"This PC`""
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

Write-Output "Enable known File Extensions within File Explorer"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

Write-Output "Tweak network configuration"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20

Write-Output "Disabling bloat services"
Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
Set-Service "HomeGroupListener" -StartupType Disabled
Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
Set-Service "HomeGroupProvider" -StartupType Disabled
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
Stop-Service "SysMain" -WarningAction SilentlyContinue
Set-Service "SysMain" -StartupType Disabled

Write-Output "Cleaning up Start Menu"
Set-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -Value '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <LayoutOptions StartTileGroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:StartLayout GroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  </DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        <taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:UWA AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        </taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      </defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '</LayoutModificationTemplate>'
$START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
$layoutFile="C:\Windows\StartMenuLayout.xml"
If(Test-Path $layoutFile)
{
    Remove-Item $layoutFile
}
$START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII
$regAliases = @("HKLM", "HKCU")
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer"
    IF(!(Test-Path -Path $keyPath)) {
        New-Item -Path $basePath -Name "Explorer"
    }
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
    Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
}
Stop-Process -name explorer
Start-Sleep -s 5
$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
Start-Sleep -s 5
foreach ($regAlias in $regAliases) {
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer"
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
}

Write-Output "Block driver updates from Windows Updates"
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1

Write-Output "Disable Windows Update automatic reboot without consent"
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0

Write-Output "[2/x] Remote Monitoring and Management"
Write-Output "Requiring Local Device Administrator to change password on next login"
net user simpatico /logonpasswordchg:yes

Write-Output "Renaming computer"
switch ($ComputerInfo.PowerPlatformRole) {
    "Mobile"    {
        Rename-Computer -Force ("LT-" + $ComputerInfo.BiosSeralNumber)
        Write-Output ("Renamed computer to LT-" + $ComputerInfo.BiosSeralNumber)
    } # Typo in Get-ComputerInfo, since we're using built-in PS the fix won't be merged. https://github.com/PowerShell/PowerShell/pull/3167#issuecomment-725418201
    "Desktop"   
    {
        Rename-Computer -Force ("DT-" + $ComputerInfo.BiosSeralNumber)
        Write-Output ("Renamed computer to DT-" + $ComputerInfo.BiosSeralNumber)
    }
    "Slate"     {
        Rename-Computer -Force ("TB-" + $ComputerInfo.BiosSeralNumber)
        Write-Output ("Renamed computer to TB-" + $ComputerInfo.BiosSeralNumber)
    }
    default     {
        Rename-Computer -Force $ComputerInfo.BiosSerialNumber
        Write-Output ("Unknown Platform " + $ComputerInfo.PowerPlatformRole)
    }
}

Write-Output "Enabling Remote Desktop"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -PropertyType DWord -Name fDenyTSConnections -Value 0 -Force
New-NetFirewallRule -DisplayName "Remote Desktop" -Group "Remote Desktop" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Enabled True

Write-Output "Installing NCentral Agent"
Start-Process -NoNewWindow -Wait -FilePath "`"$($USBDrive.DeviceId)\AutoDeploy\Applications\NCentralAgent.exe`"" -ArgumentList "/quiet"

Write-Output "Waiting for NCentral Agent install to complete ..."
## not the most elegant, but it works
while (!(Get-Process -Name "BASupSrvc" -ErrorAction SilentlyContinue)) {
    Start-Sleep -Seconds 1
}
Write-Output "NCentral Agent installed, continuing!"

Write-Output "[3/x] Device Security"
Write-Output "Configuring local Password Policy"
net accounts /uniquepw:10
net accounts /maxpwage:90
net accounts /minpwage:0
net accounts /minpwlen:12

Write-Output "Configuring local Account Security Policy"
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30

Write-Output "Enabling PasswordComplexity"
secedit /export /cfg c:\secpol.cfg
(Get-Content C:\secpol.cfg) -Replace "PasswordComplexity = 0","PasswordComplexity = 1" | Out-File C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
Remove-Item C:\secpol.cfg -Force

Write-Output "Disabling LLMNR"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -PropertyType DWord -Name EnableMulticast -Value 0 -Force

Write-Output "Disabling NBT-NS"
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

Write-Output "Securing SMB"
Set-SmbServerConfiguration -EnableAuthenticateUserSharing $True -RequireSecuritySignature $True -EnableSecuritySignature $True -EncryptData $True

Write-Output "Enabling Bitlocker and saving to AutoDeploy USB"
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -RecoveryKeyPath "$($USBDrive.DeviceId)\AutoDeploy\BitLocker\" -RecoveryKeyProtector

Write-Output "[4/x] Bloatware"
$WhitelistedUWPApps = @("MicrosoftWindows.Client.WebExperience", "Microsoft.WindowsStore", "Microsoft.WindowsNotepad", "Microsoft.WindowsCalculator", "Microsoft.WebpImageExtension", "Microsoft.VP9VideoExtensions", "Microsoft.StorePurchaseApp", "Microsoft.SecHealthUI", "Microsoft.ScreenSketch", "Microsoft.HEIFImageExtension", "Microsoft.AV1VideoExtension")
Write-Output "Removing provisioned UWP bloatware"
foreach ($package in (Get-AppxProvisionedPackage -Online)) {
    if ($WhitelistedUWPApps -notcontains $package.DisplayName) {
        Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction SilentlyContinue
    }
}
Write-Output "Removing installed UWP bloatware"
foreach ($package in Get-AppxPackage) {
    if ($WhitelistedUWPApps -notcontains $package.Name) {
        Start-Process -NoNewWindow -Wait -RedirectStandardOutput "C:\AutoDeploy\Logs\RevoUninstaller.log" -FilePath "$($USBDrive.DeviceId)\AutoDeploy\Applications\RevoUninstaller\x64\RevoUnPro.exe" -ArgumentList "/wa `"$package.Name`""
    }
}

Write-Output "Removing bloatware capabilities"
$BloatwareCapabilities = @(
    "App.StepsRecorder~~~~0.0.1.0",
    "App.Support.QuickAssist~~~~0.0.1.0",
    "Browser.InternetExplorer~~~~0.0.11.0",
    "MathRecognizer~~~~0.0.1.0",
    "Media.WindowsMediaPlayer~~~~0.0.12.0",
    "Microsoft.Windows.MSPaint~~~~0.0.1.0",
    "Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0",
    "Microsoft.Windows.WordPad~~~~0.0.1.0",
    "OpenSSH.Client~~~~0.0.1.0",
    "Print.Fax.Scan~~~~0.0.1.0",
    "XPS.Viewer~~~~0.0.1.0"
)
foreach ($item in $BloatwareCapabilities) {
    Write-Output "Removing $item"
    Remove-WindowsCapability -Online -Name $item -ErrorAction SilentlyContinue
}

Write-Output "Removing Win32 bloatware"
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
    Write-Output "Removing $($programData.Name)"
    Start-Process -NoNewWindow -Wait -RedirectStandardOutput "C:\AutoDeploy\Logs\RevoUninstaller\$($programData.Name)_32bit.log" -FilePath "$($USBDrive.DeviceId)\AutoDeploy\Applications\RevoUninstaller\x64\RevoUnPro.exe" -ArgumentList "/mu `"$($programData.Name)`" /path `"C:\Program Files (x86)\$($programData.Path)`" /mode Advanced /32"
    Start-Process -NoNewWindow -Wait -RedirectStandardOutput "C:\AutoDeploy\Logs\RevoUninstaller\$($programData.Name)_64bit.log" -FilePath "$($USBDrive.DeviceId)\AutoDeploy\Applications\RevoUninstaller\x64\RevoUnPro.exe" -ArgumentList "/mu `"$($programData.Name)`" /path `"C:\Program Files\$($programData.Path)`" /mode Advanced /64"
}

Write-Output "[5/x] Install Applications and Features"
Write-Output "Installing winget"
$WinGetPackages = @("Microsoft.UI.Xaml.2.7_7.2208.15002.0_x64__8wekyb3d8bbwe.Appx","Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe.Appx","Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe.Appx","Microsoft.DesktopAppInstaller_2022.927.3.0_neutral_~_8wekyb3d8bbwe.Msixbundle")
foreach ($packageName in $WinGetPackages) {
    Add-AppxPackage -Path "$($USBDrive.DeviceId)\AutoDeploy\Applications\WinGet\$packageName"
}

Write-Output "Installing generic applications"
$Applications = @(
    "Mozilla.Firefox.ESR",
    "Microsoft.Office",
    "Adobe.Acrobat.Reader.64-bit",
    "7zip.7zip",
    "Zoom.Zoom",
    "Microsoft.WindowsTerminal",
    "EclipseAdoptium.Temurin.8.JRE",
    "EclipseAdoptium.Temurin.11.JRE",
    "EclipseAdoptium.Temurin.17.JRE",
    "Microsoft.DotNet.DesktopRuntime.5",
    "Microsoft.DotNet.DesktopRuntime.6",
    "Microsoft.DotNet.DesktopRuntime.7"
)
foreach ($applicationName in $Applications) {
    Write-Output "Installing $applicationName"
    winget install $applicationName --silent --accept-package-agreements --accept-source-agreements
    #Start-Process -NoNewWindow -Wait -RedirectStandardOutput "C:\AutoDeploy\Logs\WinGet\$applicationName.log" -FilePath winget -ArgumentList "install $programName --silent --accept-package-agreements --accept-source-agreements"
}

Write-Output "Installing manufacturer-specific applications"
switch ($ComputerInfo.CsManufacturer) {
    {$_ -match "Dell"} {
        Write-Output "Manufacturer is Dell"

        Write-Output "Installing Dell Command | Update"
        winget install Dell.CommandUpdate --silent

        Write-Output "Installing Dell driver updates, please wait ..."
        Start-Process -NoNewWindow -Wait -FilePath "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/configure -silent -autoSuspendBitLocker=enable -userContent=disable"
        Start-Process -NoNewWindow -Wait -FilePath "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "-outputLog=C:\AutoDeploy\Logs\DCUScan.log"
        Start-Process -NoNewWindow -Wait -FilePath "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/applyUpdates -reboot=disable -outputLog=C:\AutoDeploy\Logs\DCUApply.log"
    }
}

Write-Output "Installing Windows Features"
Add-WindowsCapability -Online -Name "Print.Management.Console~~~~0.0.1.0"
Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All

Write-Output "[6/6] Cleanup"
Write-Output "Removing Setup.ps1"
Remove-Item C:\AutoDeploy\Setup.ps1 -Force
Write-Output "Removing AutoLogin"
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogin -Force
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Force
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Force

Write-Output "Performing Disk Cleanup"
cleanmgr.exe /sagerun:1 /verylowdisk

Write-Output "Creating Restore Point Checkpoint"
Checkpoint-Computer -Description "AutoDeploy" -RestorePointType "MODIFY_SETTINGS"

Write-Output "Setup Complete, rebooting"
Restart-Computer -Force