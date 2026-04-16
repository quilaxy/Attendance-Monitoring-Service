# EncryptConfig.ps1
# Configuration Encryption Script
# Encrypts appsettings.json using Windows DPAPI (LocalMachine scope)
# Must run as Administrator

param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "appsettings.json"
)

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Configuration Encryption Tool" -ForegroundColor Cyan
Write-Host "  Windows DPAPI (LocalMachine)" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "How to run as Administrator:" -ForegroundColor Yellow
    Write-Host "1. Right-click PowerShell" -ForegroundColor White
    Write-Host "2. Select 'Run as Administrator'" -ForegroundColor White
    Write-Host "3. Navigate to this folder: cd <folder>" -ForegroundColor White
    Write-Host "4. Run: .\EncryptConfig.ps1" -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Resolve full path of config file
if ([System.IO.Path]::IsPathRooted($ConfigPath)) {
    $ConfigFullPath = $ConfigPath
} else {
    $ConfigFullPath = Join-Path (Get-Location) $ConfigPath
    $ConfigFullPath = [System.IO.Path]::GetFullPath($ConfigFullPath)
}

# Check if config file exists
if (-not (Test-Path $ConfigFullPath)) {
    Write-Host "ERROR: Configuration file not found!" -ForegroundColor Red
    Write-Host "Looking for: $ConfigFullPath" -ForegroundColor Yellow
    Write-Host "Current directory: $(Get-Location)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Files in current directory:" -ForegroundColor Yellow
    Get-ChildItem | Format-Table Name
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Generate output path in SAME folder as input file
$ConfigFileInfo = Get-Item $ConfigFullPath
$OutputPath = Join-Path $ConfigFileInfo.Directory.FullName "$($ConfigFileInfo.Name).encrypted"

Write-Host "DEBUG INFO:" -ForegroundColor Cyan
Write-Host "  Input file:  $ConfigFullPath" -ForegroundColor White
Write-Host "  Output file: $OutputPath" -ForegroundColor White
Write-Host "  Folder:      $($ConfigFileInfo.Directory.FullName)" -ForegroundColor Gray
Write-Host ""

try {
    Write-Host "[1/4] Reading configuration file..." -ForegroundColor Yellow
    $configContent = Get-Content $ConfigFullPath -Raw

    # Validate JSON
    try {
        $null = ConvertFrom-Json $configContent -ErrorAction Stop
        Write-Host "      [OK] Valid JSON format" -ForegroundColor Green
    }
    catch {
        Write-Host "      [WARNING] File may not be valid JSON!" -ForegroundColor Red
        Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Red
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -ne "y") {
            exit 1
        }
    }

    Write-Host "[2/4] Converting to bytes..." -ForegroundColor Yellow
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($configContent)
    Write-Host "      [OK] Size: $($bytes.Length) bytes" -ForegroundColor Green

    Write-Host "[3/4] Encrypting with DPAPI (LocalMachine scope)..." -ForegroundColor Yellow
    Add-Type -AssemblyName System.Security
    $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    Write-Host "      [OK] Encrypted size: $($encryptedBytes.Length) bytes" -ForegroundColor Green

    Write-Host "[4/4] Saving encrypted file..." -ForegroundColor Yellow

    # Delete old file if exists
    if (Test-Path $OutputPath) {
        Write-Host "      - Removing old encrypted file..." -ForegroundColor Gray
        Remove-Item $OutputPath -Force
    }

    # Save raw encrypted bytes directly (no Base64)
    [System.IO.File]::WriteAllBytes($OutputPath, $encryptedBytes)

    # Verify file was created
    if (-not (Test-Path $OutputPath)) {
        throw "Failed to create encrypted file at: $OutputPath"
    }

    $createdFile = Get-Item $OutputPath
    Write-Host "      [OK] Saved to: $($createdFile.FullName)" -ForegroundColor Green
    Write-Host "      [OK] File size: $($createdFile.Length) bytes" -ForegroundColor Green

    Write-Host ""
    Write-Host "======================================" -ForegroundColor Green
    Write-Host "         ENCRYPTION SUCCESS!          " -ForegroundColor Green
    Write-Host "======================================" -ForegroundColor Green
    Write-Host ""

    # Verify by attempting to decrypt
    Write-Host "Verifying encryption..." -ForegroundColor Cyan

    # Read back as raw bytes
    $testEncryptedBytes = [System.IO.File]::ReadAllBytes($OutputPath)

    # Decrypt
    $testDecryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $testEncryptedBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    $testDecryptedText = [System.Text.Encoding]::UTF8.GetString($testDecryptedBytes)

    if ($testDecryptedText -eq $configContent) {
        Write-Host "[OK] Verification successful - File can be decrypted correctly" -ForegroundColor Green
    } else {
        Write-Host "[FAILED] Verification failed - Decrypted content does not match!" -ForegroundColor Red
        Write-Host "This should not happen. Please try again." -ForegroundColor Red
        exit 1
    }

    Write-Host ""
    Write-Host "FILE LOCATION:" -ForegroundColor Yellow
    Write-Host "  $($createdFile.FullName)" -ForegroundColor White
    Write-Host ""

    # Open folder in Windows Explorer
    Write-Host "Opening folder in Windows Explorer..." -ForegroundColor Cyan
    Start-Process explorer.exe -ArgumentList "/select,`"$($createdFile.FullName)`""

    Write-Host ""
    Write-Host "IMPORTANT SECURITY STEPS:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. DELETE the original file:" -ForegroundColor White
    Write-Host "   del `"$ConfigFullPath`"" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "2. DELETE this encryption script:" -ForegroundColor White
    Write-Host "   del EncryptConfig.ps1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "3. Deploy ONLY these files:" -ForegroundColor White
    Write-Host "   - Attendance-Monitoring-Service.exe" -ForegroundColor Cyan
    Write-Host "   - $($createdFile.Name)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "SECURITY NOTES:" -ForegroundColor Yellow
    Write-Host "[OK] Only administrators can decrypt this file" -ForegroundColor Green
    Write-Host "[OK] Can only be decrypted on THIS machine" -ForegroundColor Green
    Write-Host "[OK] If you move to different PC, must re-encrypt there" -ForegroundColor Green
    Write-Host ""

} catch {
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Red
    Write-Host "         ENCRYPTION FAILED!           " -ForegroundColor Red
    Write-Host "======================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack trace:" -ForegroundColor Yellow
    Write-Host $_.Exception.StackTrace -ForegroundColor Gray
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Press Enter to exit..."
Read-Host
