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
rem  Banner
rem ============================================================
echo ============================================================
echo  WinTune - Full Coverage Run
echo ============================================================
echo  Location: %SCRIPT_DIR%
echo  Tuning (see top of this .bat to override):
echo    Driver max size     : %WT_DRIVER_MAX_SIZE_MB% MB
if "%WT_DRIVER_MAX_STALE_DAYS%"=="" (
    echo    Driver max stale    : auto-adapt ^(WinTune.ps1 default^)
) else (
    echo    Driver max stale    : %WT_DRIVER_MAX_STALE_DAYS% days
)
echo    Driver min age      : %WT_DRIVER_MIN_AGE_DAYS% days
echo    Installer orphan MB : %WT_INSTALLER_MIN_ORPHAN_MB%
echo    Installer age days  : %WT_INSTALLER_MIN_AGE_DAYS%
echo    Package cache MB    : %WT_PACKAGE_CACHE_MIN_TOTAL_MB% ^(total^)
echo    Feature deferral    : %WT_FEATURE_UPDATE_DELAY_DAYS% days
echo.
echo  Continuing in 5 seconds. Press Ctrl+C to abort.
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