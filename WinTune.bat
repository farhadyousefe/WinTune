@echo off
setlocal

rem ---- Locate this script's directory ----
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

rem ============================================================
rem  TUNING KNOBS - edit these per PC if needed
rem  (leave blank to use WinTune.ps1's own defaults)
rem ============================================================
rem  Driver gates:
rem    WT_DRIVER_MAX_SIZE_MB     - max driver size to install (default 2048; raise to 3072 for NVIDIA DCH)
rem    WT_DRIVER_MAX_STALE_DAYS  - max driver age to install (default 2555 = 7yr; blank for auto-adapt)
rem    WT_DRIVER_MIN_AGE_DAYS    - min driver age to install (default 30; keep to avoid bleeding-edge)
set "WT_DRIVER_MAX_SIZE_MB=2048"
set "WT_DRIVER_MAX_STALE_DAYS="
set "WT_DRIVER_MIN_AGE_DAYS=30"

rem  Installer / package-cache cleanup gates (destructive):
rem    WT_INSTALLER_MIN_ORPHAN_MB  - min total orphan size to trigger (default 500 MB)
rem    WT_INSTALLER_MIN_AGE_DAYS   - MSI/MSP age cutoff (default 180 days)
rem    WT_PACKAGE_CACHE_MIN_AGE_DAYS - superseded folder age (default 30 days)
rem    WT_PACKAGE_CACHE_MIN_SIZE_MB  - min folder size (default 5 MB)
rem    WT_PACKAGE_CACHE_MIN_TOTAL_MB - min total candidate size (default 100 MB)
set "WT_INSTALLER_MIN_ORPHAN_MB=500"
set "WT_INSTALLER_MIN_AGE_DAYS=180"
set "WT_PACKAGE_CACHE_MIN_AGE_DAYS=30"
set "WT_PACKAGE_CACHE_MIN_SIZE_MB=5"
set "WT_PACKAGE_CACHE_MIN_TOTAL_MB=100"

rem  Feature update deferral (default 30 days)
set "WT_FEATURE_UPDATE_DELAY_DAYS=30"

rem ============================================================
rem  Windows Update runner retry policy (Step 39 detached child):
rem    WT_WU_MAX_RETRIES - max install attempts per update (default 3, cap 10)
rem    Retries only fire for TRANSIENT failures (busy, service stopped,
rem    timeout, aborted). Permanent failures (not applicable, signature
rem    error, payload missing) give up immediately.
rem    Set to 1 to disable retries entirely.
rem    Backoff: 30s, 60s, 90s, ... (30 * (attempt-1) seconds).
set "WT_WU_MAX_RETRIES=3"

rem ============================================================
rem  Verify prerequisites
rem ============================================================
if not exist "%SCRIPT_DIR%\WinTune.ps1" (
    echo [ERROR] WinTune.ps1 not found in: %SCRIPT_DIR%
    pause
    exit /b 1
)

powershell.exe -NoProfile -Command "if ($PSVersionTable.PSVersion.Major -lt 5) { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Windows PowerShell 5.1 or newer is required.
    pause
    exit /b 1
)

rem ============================================================
rem  Banner - WHAT THIS RUN DOES
rem ============================================================
echo ============================================================
echo  WinTune Ultimate - Full Coverage Run
echo ============================================================
echo  Location : %SCRIPT_DIR%
echo  Log      : %SCRIPT_DIR%\WinTune.log
echo  Report   : %SCRIPT_DIR%\Reports\WinTune_Report_TIMESTAMP.html
echo.
echo ------------------------------------------------------------
echo  SAFETY NET FIRST - Step 25 creates a "WinTune_PreChange"
echo  System Restore point BEFORE any change. Every step below
echo  can be rolled back from that snapshot.
echo ------------------------------------------------------------
echo.
echo  CLEANUP (Steps 1-9, 34, 40-43):
echo    - System + user temp, caches, CBS/DISM logs
echo    - All Recycle Bins on fixed drives
echo    - Chrome / Edge / Brave / Vivaldi + Firefox caches
echo    - Office / Outlook temp + secure OLK attachment cache
echo    - Adobe / Foxit / SumatraPDF PDF reader caches
echo    - Copilot / VS Code / Teams developer caches
echo    - Interactive AppData scan (Spotify / Discord / npm / etc.)
echo    - Explorer thumbnail + icon caches
echo    - Broken desktop shortcuts
echo    - Font cache + Explorer icon index rebuild
echo    - Orphaned Windows Installer MSI/MSP files     [GATED]
echo    - Defender scan caches
echo    - Superseded Package Cache folders             [GATED]
echo    - Safe-listed UWP LocalCache folders
echo.
echo  PERFORMANCE (Steps 10-11, 24-28, 45-47, 49, 52, 54-55):
echo    - Telemetry services to Manual + 14 tasks disabled
echo    - Advertising ID off
echo    - Taskbar End-Task on; Game DVR recording off
echo    - HDD defrag only (SSDs handled by Windows TRIM)
echo    - Balanced power plan + overlay
echo    - Transparency + animations off (ClearType kept)
echo    - Windows 10-style context menu (Win11 only)
echo    - Storage Sense weekly cleanup (Downloads protected)
echo    - Prefetcher disabled on all-SSD (SysMain stays running)
echo    - Delivery Optimization set to LAN-only
echo    - CapabilityAccessManager WAL audit
echo    - Safe service trim (5 services)
echo    - Privacy + Start Menu hardening
echo    - TCP tuning: RSS + auto-tune + CUBIC (skipped if VPN active)
echo.
echo  SECURITY HARDENING (Steps 29-32, 49, 56):
echo    - SMBv1 disabled (feature + registry)
echo    - LLMNR + WPAD disabled (credential-theft vectors)
echo    - DNS over HTTPS enabled
echo    - Defender ASR rules in Audit mode (7 rules)
echo    - AutoRun disabled on all drives
echo    - WebClient disabled (skipped on domain-joined)
echo    - WPAD hosts entry added
echo    - PowerShell ScriptBlockLogging enabled
echo.
echo  UPDATE ORCHESTRATION (detached windows):
echo    - Step 8b: Driver audit + install eligible     [GATED]
echo    - Step 12: SFC + DISM (CheckHealth/scannow/RestoreHealth)
echo    - Step 33: Winget upgrades (enumerate + confirm + install)
echo    - Step 39: Windows Update (Security/Critical/Defender only)
echo    - Step 37: Feature update deferral
echo.
echo  DIAGNOSTIC AUDITS (read-only):
echo    - Step 18: DriverStore inventory
echo    - Step 19: startup programs inventory
echo    - Step 20: scheduled tasks inventory
echo    - Step 51: orphaned uninstall entries
echo    - Step 56: security posture (UAC/SMB/BitLocker/LAPS/etc.)
echo.
echo  Detached windows: Steps 8b/12/33/39 launch in their own
echo  visible windows. WinTune continues immediately. See their
echo  logs at WinTune_Drivers.log, WinTune_SfcDism.log,
echo  WinTune_Winget.log, WinTune_WU.log in %SCRIPT_DIR%.
echo.
echo ------------------------------------------------------------
echo  CURRENT TUNING GATES (edit at top of this .bat to override)
echo ------------------------------------------------------------
echo  Driver gates:
echo    Min age          : %WT_DRIVER_MIN_AGE_DAYS% days
if "%WT_DRIVER_MAX_STALE_DAYS%"=="" (
    echo    Max age          : auto-adapt ^(WinTune.ps1 default^)
) else (
    echo    Max age          : %WT_DRIVER_MAX_STALE_DAYS% days
)
echo    Max size         : %WT_DRIVER_MAX_SIZE_MB% MB
echo.
echo  Destructive cleanup gates:
echo    Installer orphan : %WT_INSTALLER_MIN_ORPHAN_MB% MB minimum
echo    Installer age    : %WT_INSTALLER_MIN_AGE_DAYS% days
echo    Pkg cache age    : %WT_PACKAGE_CACHE_MIN_AGE_DAYS% days
echo    Pkg cache size   : %WT_PACKAGE_CACHE_MIN_SIZE_MB% MB
echo    Pkg cache total  : %WT_PACKAGE_CACHE_MIN_TOTAL_MB% MB
echo.
echo  Windows Update:
echo    Feature deferral : %WT_FEATURE_UPDATE_DELAY_DAYS% days
if "%WT_WU_MAX_RETRIES%"=="" (
    echo    Max retries      : WinTune.ps1 default ^(3^)
) else (
    echo    Max retries      : %WT_WU_MAX_RETRIES% ^(transient only^)
)
echo.
echo ------------------------------------------------------------
echo  DESTRUCTIVE STEPS ENABLED IN THIS RUN
echo ------------------------------------------------------------
echo  - Step 35: Remove non-essential provisioned AppX packages
echo  - Step 38: Disable non-essential startup entries
echo  - Step 40: Delete orphaned Windows Installer MSI/MSP files
echo  - Step 42: Delete superseded Package Cache folders
echo  - Step 50: Disable non-essential context menu handlers
echo  - Step 51: Delete orphaned uninstall registry entries
echo.
echo  Each has size/age or signature gates, but they are IRREVERSIBLE.
echo  To run audit-only, remove the corresponding flags from the
echo  powershell.exe command below:
echo    -AllowInstallerCleanup  -AllowPackageCacheCleanup
echo    -AllowProgramAuditAction  -RemoveBloatware
echo    -AllowPersistenceAction  -AllowContextMenuAction
echo.
echo ------------------------------------------------------------
echo  NOT INCLUDED IN THIS RUN (add flags manually if needed)
echo ------------------------------------------------------------
echo  -AllowResetBase            irreversible - lose update uninstall
echo  -AllowNetworkReset         drops network until reboot
echo  -AllowUltimatePerformance  forces 100%% CPU on battery
echo  -AllowMalwareScan          only if Malwarebytes installed
echo  -AllowCatrootReset         clears signature cache
echo.
echo ============================================================
echo  Press Ctrl+C to abort. Continuing in 5 seconds...
echo ============================================================
timeout /t 5 /nobreak >nul

rem ============================================================
rem  Build the argument string
rem  (Driver gates use WT_ vars if set, otherwise ps1 default)
rem ============================================================
set "WT_ARGS="
set "WT_ARGS=%WT_ARGS% -Preset Full -YesToAll"
set "WT_ARGS=%WT_ARGS% -AllowDismRestore -AllowPrefetch -AllowWinget"
set "WT_ARGS=%WT_ARGS% -RemoveBloatware -AllowSearchDefrag -RemoveStartups"
set "WT_ARGS=%WT_ARGS% -InstallUpdates -AllowInstallerCleanup"
set "WT_ARGS=%WT_ARGS% -AllowPackageCacheCleanup -AllowUwpCleanup"
set "WT_ARGS=%WT_ARGS% -AllowSysMainTuning -AllowDoTuning -AllowCamWALCleanup"
set "WT_ARGS=%WT_ARGS% -AllowPersistenceAction -AllowScheduledTaskAction"
set "WT_ARGS=%WT_ARGS% -AllowAutoRunDisable -AllowContextMenuAction"
set "WT_ARGS=%WT_ARGS% -AllowProgramAuditAction -AllowDriverUpdates"
set "WT_ARGS=%WT_ARGS% -AllowServiceTrim -AllowPrivacyTweaks -AllowTcpTuning"
set "WT_ARGS=%WT_ARGS% -AllowVbsAudit -AllowUnknownPackageVersions"
set "WT_ARGS=%WT_ARGS% -DisableWebClient -AddWpadHostsEntry -EnableScriptBlockLogging"

if not "%WT_DRIVER_MAX_SIZE_MB%"==""    set "WT_ARGS=%WT_ARGS% -DriverMaxSizeMB %WT_DRIVER_MAX_SIZE_MB%"
if not "%WT_DRIVER_MAX_STALE_DAYS%"=="" set "WT_ARGS=%WT_ARGS% -DriverMaxStaleDays %WT_DRIVER_MAX_STALE_DAYS%"
if not "%WT_DRIVER_MIN_AGE_DAYS%"==""   set "WT_ARGS=%WT_ARGS% -DriverMinAgeDays %WT_DRIVER_MIN_AGE_DAYS%"
if not "%WT_INSTALLER_MIN_ORPHAN_MB%"=="" set "WT_ARGS=%WT_ARGS% -InstallerMinOrphanMB %WT_INSTALLER_MIN_ORPHAN_MB%"
if not "%WT_INSTALLER_MIN_AGE_DAYS%"==""  set "WT_ARGS=%WT_ARGS% -InstallerMinAgeDays %WT_INSTALLER_MIN_AGE_DAYS%"
if not "%WT_PACKAGE_CACHE_MIN_AGE_DAYS%"=="" set "WT_ARGS=%WT_ARGS% -PackageCacheMinAgeDays %WT_PACKAGE_CACHE_MIN_AGE_DAYS%"
if not "%WT_PACKAGE_CACHE_MIN_SIZE_MB%"==""  set "WT_ARGS=%WT_ARGS% -PackageCacheMinSizeMB %WT_PACKAGE_CACHE_MIN_SIZE_MB%"
if not "%WT_PACKAGE_CACHE_MIN_TOTAL_MB%"=="" set "WT_ARGS=%WT_ARGS% -PackageCacheMinTotalMB %WT_PACKAGE_CACHE_MIN_TOTAL_MB%"
if not "%WT_FEATURE_UPDATE_DELAY_DAYS%"=="" set "WT_ARGS=%WT_ARGS% -FeatureUpdateDelayDays %WT_FEATURE_UPDATE_DELAY_DAYS%"

rem ============================================================
rem  Promote WT_WU_MAX_RETRIES to env var that the WU runner
rem  actually reads. This is different from the WT_ARGS pattern
rem  because the WU runner is a detached child - it doesn't see
rem  WinTune.ps1's parameters, only env vars inherited at launch.
rem ============================================================
if not "%WT_WU_MAX_RETRIES%"=="" set "FC_WU_MAX_RETRIES=%WT_WU_MAX_RETRIES%"

rem ============================================================
rem  Launch
rem ============================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\WinTune.ps1" %WT_ARGS%
set "WT_EXIT=%errorlevel%"

echo.
echo ============================================================
echo  WinTune finished. Exit code: %WT_EXIT%
echo ============================================================
pause
endlocal & exit /b %WT_EXIT%