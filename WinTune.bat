@echo off
setlocal

rem ---- Locate this script's directory ----
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

rem ---- Verify WinTune.ps1 is alongside ----
if not exist "%SCRIPT_DIR%\WinTune.ps1" (
    echo [ERROR] WinTune.ps1 not found in: %SCRIPT_DIR%
    echo         Place this .bat file alongside WinTune.ps1
    pause
    exit /b 1
)

rem ---- Verify PowerShell 5.1+ is available ----
powershell.exe -NoProfile -Command "if ($PSVersionTable.PSVersion.Major -lt 5) { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Windows PowerShell 5.1 or newer is required.
    echo         This is bundled with Windows 10 and 11 by default.
    pause
    exit /b 1
)

echo ============================================================
echo  WinTune - Full Coverage Run
echo ============================================================
echo  Location: %SCRIPT_DIR%
echo.
echo  This will run all 55 steps, with these optional flags enabled:
echo    - System Restore Point     (runs FIRST as a safety snapshot)
echo    - DISM RestoreHealth       (5-25 min, detached window)
echo    - Prefetch purge           (slows app launches temporarily)
echo    - Winget upgrades          (10-60 min, detached window)
echo    - Bloatware removal        (removes non-essential AppX)
echo    - Startup removal          (interactive; auto-yes)
echo    - Windows Update           (10-60 min, detached window)
echo    - Installer cleanup        (orphaned MSI/MSP deletion)
echo    - Package cache cleanup    (superseded installers deletion)
echo    - UWP LocalCache sweep
echo    - SysMain tuning           (SSD-only)
echo    - Delivery Optimization    (LAN-only)
echo    - CamWAL detection/clean   (if bloated)
echo    - Persistence action       (disable non-essential autoruns)
echo    - AutoRun disable          (USB/CD autorun.inf blocked)
echo    - Context menu cleanup     (disable non-essential shell extensions)
echo    - Program audit            (delete orphaned uninstall entries)
echo    - Driver updates           (audit + install eligible; firmware excluded)
echo    - Search index defrag      (15-45 min; disables Search temporarily)
echo    - Safe service trim        (5 services to Manual/Disabled)
echo    - Privacy tweaks           (HKCU privacy + Start Menu hardening)
echo    - TCP performance tuning   (RSS + Auto-Tuning + CUBIC)
echo    - VBS / HVCI audit         (informational; no changes)
echo    - Include unknown pkg vers (winget --include-unknown)
echo.
echo  Driver update safety gates:
echo    - Min age 30 days          (skips very fresh drivers)
echo    - Max size 2048 MB         (skips corrupt manifests)
echo    - Max stale 1825 days      (skips 5+ year old drivers)
echo.
echo  WARNING - Destructive steps enabled in this run:
echo    - Step 40: Deletes orphaned Windows Installer cache files
echo    - Step 42: Deletes superseded Package Cache folders
echo    - Step 51: Deletes orphaned uninstall registry entries
echo.
echo  Each is gated by size/age thresholds, but they are IRREVERSIBLE.
echo  To run in audit-only mode instead, remove the corresponding flags
echo  from the powershell.exe command below:
echo    -AllowInstallerCleanup  -AllowPackageCacheCleanup
echo    -AllowProgramAuditAction
echo.
echo  NOT included (add manually if you accept the risk):
echo    -AllowResetBase            (irreversible - lose update uninstall)
echo    -AllowNetworkReset         (drops network until reboot)
echo    -AllowUltimatePerformance  (forces 100%% CPU on battery)
echo    -AllowMalwareScan          (only if Malwarebytes installed)
echo    -AllowCatrootReset         (clears signature cache)
echo.
echo ============================================================
echo  Press Ctrl+C now to abort. Continuing in 5 seconds...
echo ============================================================
timeout /t 5 /nobreak

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\WinTune.ps1" -Preset Full -YesToAll -AllowDismRestore -AllowPrefetch -AllowWinget -RemoveBloatware -AllowSearchDefrag -RemoveStartups -InstallUpdates -AllowInstallerCleanup -AllowPackageCacheCleanup -AllowUwpCleanup -AllowSysMainTuning -AllowDoTuning -AllowCamWALCleanup -AllowPersistenceAction -AllowAutoRunDisable -AllowContextMenuAction -AllowProgramAuditAction -AllowDriverUpdates -DriverMaxSizeMB 2048 -DriverMaxStaleDays 1825 -AllowServiceTrim -AllowPrivacyTweaks -AllowTcpTuning -AllowVbsAudit -AllowUnknownPackageVersions

echo.
echo ============================================================
echo  WinTune finished. Exit code: %errorlevel%
echo ============================================================
pause
endlocal