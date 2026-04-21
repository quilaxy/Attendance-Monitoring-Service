[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetVersion,

    [string]$ServiceName = "Attendance-Service",
    [string]$InstallDirectory = "C:\Program Files\Attendance-Monitoring-Service",
    [string]$ExecutableName = "Attendance-Monitoring-Service.exe",
    [string]$RegistryKeyPath = "HKLM:\SOFTWARE\Attendance-Monitoring-Service",
    [string]$RegistryValueName = "InstalledVersion"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExitCodeSuccess = 0
$ExitCodePackageMissing = 10
$ExitCodeStopFailed = 11
$ExitCodeCopyFailed = 12
$ExitCodeStartFailed = 13
$ExitCodeRollbackFailed = 14

$scriptDirectory = Split-Path -Parent $PSCommandPath
$packageExePath = Join-Path $scriptDirectory $ExecutableName
$targetExePath = Join-Path $InstallDirectory $ExecutableName
$backupExePath = "$targetExePath.bak"

if (-not (Test-Path -LiteralPath $packageExePath)) {
    Write-Error "Package executable not found at: $packageExePath"
    exit $ExitCodePackageMissing
}

if (-not (Test-Path -LiteralPath $InstallDirectory)) {
    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
}

$serviceExists = $false
$serviceWasRunning = $false

try {
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    $serviceExists = $true
    $serviceWasRunning = $service.Status -eq 'Running'

    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    }
}
catch {
    if ($serviceExists) {
        Write-Error "Failed to stop service '$ServiceName'. $_"
        exit $ExitCodeStopFailed
    }

    Write-Warning "Service '$ServiceName' not found. Continuing with file update only."
}

if (Test-Path -LiteralPath $targetExePath) {
    Copy-Item -LiteralPath $targetExePath -Destination $backupExePath -Force
}

try {
    Copy-Item -LiteralPath $packageExePath -Destination $targetExePath -Force
}
catch {
    Write-Error "Failed to copy new executable to '$targetExePath'. $_"
    exit $ExitCodeCopyFailed
}

try {
    if (-not (Test-Path -LiteralPath $RegistryKeyPath)) {
        New-Item -Path $RegistryKeyPath -Force | Out-Null
    }

    Set-ItemProperty -Path $RegistryKeyPath -Name $RegistryValueName -Value $TargetVersion -Type String
}
catch {
    Write-Warning "Unable to update registry marker '$RegistryKeyPath\\$RegistryValueName'. $_"
}

if ($serviceExists -and $serviceWasRunning) {
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
    }
    catch {
        Write-Warning "Failed to start updated service '$ServiceName'. Attempting rollback. $_"

        if (-not (Test-Path -LiteralPath $backupExePath)) {
            Write-Error "Rollback failed because backup executable does not exist: $backupExePath"
            exit $ExitCodeRollbackFailed
        }

        try {
            Copy-Item -LiteralPath $backupExePath -Destination $targetExePath -Force
            Start-Service -Name $ServiceName -ErrorAction Stop
            (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
        }
        catch {
            Write-Error "Rollback failed and service could not be started. $_"
            exit $ExitCodeRollbackFailed
        }

        Write-Error "Updated service failed to start, rollback restored previous executable."
        exit $ExitCodeStartFailed
    }
}

Write-Host "Update completed successfully. Version marker set to $TargetVersion"
exit $ExitCodeSuccess
