# AutoDeploy
An all-in-one deployment tool for Windows 10/11 computers. Originally built for my homelab, adapted for my job, now opening it to the public. This repository is heavily influenced by the following projects:
- [colebermudez/Windows-Deployment](https://github.com/colebermudez/Windows-Deployment)\
- [this reddit post](https://www.reddit.com/r/msp/comments/k6do1e/windows_provisioning_packages_powershell_who/)

## How does it work?
AutoDeploy combines an autounattend.xml and a Provisioning Package which runs the Install.ps1 PowerShell script. Install.ps1 performs a few sanity checks, downloads Setup.ps1 from this repository, and sets it to run once on login. Setup.ps1 is where the meat is at, performing a variety of tasks to clean up and configure a Windows install for daily use.

## How can I use it?
The autounattend.xml and Provisioning Package are the magic for setting up the lite-touch deployment. All you have to do is have the computer boot from the USB and it takes over from there. I do not have instructions for configuring the Provisioning Package yet, but will add them to the stable branch once I deem this stable.

# Pre-release Software
Please note this branch is considered pre-release software. There may be bugs and nothing is guaranteed to work.