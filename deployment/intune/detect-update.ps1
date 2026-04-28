[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetVersion,

    [string]$ExecutablePath = "C:\Program Files\Attendance-Monitoring-Service\Attendance-Monitoring-Service.exe",
    [string]$RegistryKeyPath = "HKLM:\SOFTWARE\Attendance-Monitoring-Service",
    [string]$RegistryValueName = "InstalledVersion"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$fileVersionMatched = $false
$registryVersionMatched = $false

if (Test-Path -LiteralPath $ExecutablePath) {
    try {
        $fileVersion = (Get-Item -LiteralPath $ExecutablePath).VersionInfo.FileVersion
        if ($fileVersion -eq $TargetVersion) {
            $fileVersionMatched = $true
        }
    }
    catch {
        Write-Warning "Unable to read file version from '$ExecutablePath'. $_"
    }
}

try {
    $registryValue = (Get-ItemProperty -Path $RegistryKeyPath -Name $RegistryValueName -ErrorAction Stop).$RegistryValueName
    if ($registryValue -eq $TargetVersion) {
        $registryVersionMatched = $true
    }
}
catch {
    Write-Verbose "Registry marker not available or not readable."
}

if ($fileVersionMatched -or $registryVersionMatched) {
    Write-Output "Detected version $TargetVersion"
    exit 0
}

Write-Output "Version $TargetVersion not detected"
exit 1
