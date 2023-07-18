[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

//Disable-InternetExplorerESC
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
#Stop-Process -Name Explorer -Force
Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green -Verbose


//Enable-IEFileDownload

$HKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$HKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
Set-ItemProperty -Path $HKLM -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
Set-ItemProperty -Path $HKCU -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
Set-ItemProperty -Path $HKLM -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
Set-ItemProperty -Path $HKCU -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose

//Enable-CopyPageContent-In-InternetExplorer
$HKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$HKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
Set-ItemProperty -Path $HKLM -Name "1407" -Value 0 -ErrorAction SilentlyContinue -Verbose
Set-ItemProperty -Path $HKCU -Name "1407" -Value 0 -ErrorAction SilentlyContinue -Verbose


//InstallChocolatey
$env:chocolateyUseWindowsCompression = 'true'
$env:chocolateyIgnoreRebootDetected = 'true'
$env:chocolateyVersion = '1.4.0'
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
choco feature enable -n allowGlobalConfirmation

//DisableServerMgrNetworkPopup 
cd HKLM:\
New-Item -Path HKLM:\System\CurrentControlSet\Control\Network -Name NewNetworkWindowOff -Force 
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose

//CreateLabFilesDirectory
cd HKLM:\
New-Item -Path HKLM:\System\CurrentControlSet\Control\Network -Name NewNetworkWindowOff -Force 
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose

//

//DisableWindowsFirewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

//InstallEdgeChromium
#Download and Install edge
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("http://go.microsoft.com/fwlink/?LinkID=2093437","C:\Packages\MicrosoftEdgeBetaEnterpriseX64.msi")
sleep 5

Start-Process msiexec.exe -Wait '/I C:\Packages\MicrosoftEdgeBetaEnterpriseX64.msi /qn' -Verbose 
sleep 5
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Azure Portal.lnk")
$Shortcut.TargetPath = """C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"""
$argA = """https://portal.azure.com"""
$Shortcut.Arguments = $argA 
$Shortcut.Save()

#Disable Welcome page of Microsoft Edge
#Disable Edge 'First Run' Setup

$edgePolicyRegistryPath = 'HKLM:SOFTWARE\Policies\Microsoft\Edge'
$desktopSettingsRegistryPath = 'HKCU:SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop'
$firstRunRegistryName = 'HideFirstRunExperience'
$firstRunRegistryValue = '0x00000001'
$savePasswordRegistryName = 'PasswordManagerEnabled'
$savePasswordRegistryValue = '0x00000000'
$autoArrangeRegistryName = 'FFlags'
$autoArrangeRegistryValue = '1075839525'

if (-NOT (Test-Path -Path $edgePolicyRegistryPath)) {
New-Item -Path $edgePolicyRegistryPath -Force | Out-Null
}

New-ItemProperty -Path $edgePolicyRegistryPath -Name $firstRunRegistryName -Value $firstRunRegistryValue -PropertyType DWORD -Force
New-ItemProperty -Path $edgePolicyRegistryPath -Name $savePasswordRegistryName -Value $savePasswordRegistryValue -PropertyType DWORD -Force
Set-ItemProperty -Path $desktopSettingsRegistryPath -Name $autoArrangeRegistryName -Value $autoArrangeRegistryValue -Force

#Set-Location hklm:
#Test-Path .\Software\Policies\Microsoft
#New-Item -Path .\Software\Policies\Microsoft -Name MicrosoftEdge
#New-Item -Path .\Software\Policies\Microsoft\MicrosoftEdge -Name Main
#New-ItemProperty -Path .\Software\Policies\Microsoft\MicrosoftEdge\Main -Name PreventFirstRunPage -Value "1" -Type DWORD -Force -ErrorAction SilentlyContinue | Out-Null

#Setting up the edge browser as default

Invoke-WebRequest 'https://experienceazure.blob.core.windows.net/templates/cloudlabs-common/SetUserFTA.zip' -OutFile 'C:\SetUserFTA.zip'
Expand-Archive -Path 'C:\SetUserFTA.zip' -DestinationPath 'C:\' -Force
cmd.exe /c C:\SetUserFTA\SetUserFTA.exe
cmd.exe /c cd C:\SetUserFTA
cmd.exe /c SetuserFTA http MSEdgeHTM
cmd.exe /c SetuserFTA https MSEdgeHTM
cmd.exe /c SetuserFTA .htm MSEdgeHTM
Sleep 5
Remove-Item -Path 'C:\SetUserFTA.zip'
Remove-Item -Path 'C:\SetUserFTA' -Force -Recurse

