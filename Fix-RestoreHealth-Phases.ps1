#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Adds RestoreHealth install-phase regex patterns to the log parser
    inside Invoke-NativeLive.

.DESCRIPTION
    The current parser only matches the download phase (DownloadProgress
    from CBS.log). Once download completes and DISM moves to the install
    phase, the spinner freezes. This adds three new patterns:

      - "Exec: RestoreHealth: N%"   -> "Restoring: N%"
      - "RestoreHealth: N%"          -> "Restoring: N%"
      - "RestoreHealth operation completed" -> "Restore complete"

    Backs up first, verifies parser, rolls back on failure.
#>

[CmdletBinding()]
param([string]$Path = 'D:\PS\WinTune.ps1')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' WinTune - RestoreHealth Install Phase Fix' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ("Target: {0}" -f $Path)
Write-Host ''

# Backup
$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$backup = "{0}.bak_{1}" -f $Path, $stamp
Copy-Item -LiteralPath $Path -Destination $backup -Force
Write-Host ("[OK] Backup: {0}" -f $backup) -ForegroundColor Green

# Read as UTF-8
$bytes = [System.IO.File]::ReadAllBytes($Path)
$content = (New-Object System.Text.UTF8Encoding $false).GetString($bytes)
if ($content.Length -gt 0 -and [int][char]$content[0] -eq 0xFEFF) {
    $content = $content.Substring(1)
}

# Locate the log-parsing block
$anchor = @'
                        elseif ($line -match '\[=+\s*([\d.]+)%\s*\]') {
                            $m = "DISM: $($Matches[1])% complete"
                            $rank = 3
                        }
'@

$replacement = @'
                        elseif ($line -match '\[=+\s*([\d.]+)%\s*\]') {
                            $m = "DISM: $($Matches[1])% complete"
                            $rank = 3
                        }
                        elseif ($line -match 'Exec(?:uting)?:?\s+Restore\s*Health:?\s+([\d.]+)%') {
                            $m = "Restoring: $($Matches[1])%"
                            $rank = 3
                        }
                        elseif ($line -match 'Restore\s*Health:?\s+([\d.]+)%\s+complete') {
                            $m = "Restoring: $($Matches[1])%"
                            $rank = 3
                        }
                        elseif ($line -match 'Restore\s*Health\s+operation\s+completed') {
                            $m = 'Restore complete'
                            $rank = 7
                        }
'@

$anchorN = $anchor -replace "`r`n", "`n"
$contentN = $content -replace "`r`n", "`n"

if ($contentN.Contains('Restoring: $($Matches[1])%')) {
    Write-Host '[SKIP] RestoreHealth install phase regex already present.' -ForegroundColor Yellow
    Copy-Item -LiteralPath $backup -Destination $Path -Force
    exit 0
}

if (-not $contentN.Contains($anchorN)) {
    Write-Host '[FAIL] Could not find the log parser anchor.' -ForegroundColor Red
    Write-Host '       The file may have been edited.' -ForegroundColor Yellow
    Copy-Item -LiteralPath $backup -Destination $Path -Force
    exit 1
}

$contentN = $contentN.Replace($anchorN, ($replacement -replace "`r`n", "`n"))
$content = $contentN -replace "`n", "`r`n"

# Write back as UTF-8 with BOM
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($Path, $content, $utf8Bom)
Write-Host '[OK] File written as UTF-8 with BOM.' -ForegroundColor Green

# Verify
Write-Host ''
Write-Host 'Verifying...' -ForegroundColor Cyan

$errs = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errs)
if ($errs.Count -eq 0) {
    Write-Host 'PS7 parser: OK' -ForegroundColor Green
} else {
    Write-Host ("PS7 parser: {0} errors" -f $errs.Count) -ForegroundColor Red
    $errs | Select-Object -First 3 | ForEach-Object {
        Write-Host ("  Line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) -ForegroundColor Yellow
    }
    Copy-Item -LiteralPath $backup -Destination $Path -Force
    exit 1
}

$testScript = @'
$errs = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    'D:\PS\WinTune.ps1', [ref]$null, [ref]$errs)
if ($errs.Count -eq 0) { 'OK' } else { "$($errs.Count) errors" }
'@
$testPath = Join-Path $env:TEMP 'wt-parse-51.ps1'
Set-Content -LiteralPath $testPath -Value $testScript -Encoding ASCII
$result = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $testPath
Remove-Item $testPath -Force -ErrorAction SilentlyContinue

if ($result.Trim() -eq 'OK') {
    Write-Host 'PS 5.1 parser: OK' -ForegroundColor Green
} else {
    Write-Host ("PS 5.1 parser: {0}" -f $result.Trim()) -ForegroundColor Red
    Copy-Item -LiteralPath $backup -Destination $Path -Force
    exit 1
}

Write-Host ''
Write-Host 'PATCH COMPLETE' -ForegroundColor Green
