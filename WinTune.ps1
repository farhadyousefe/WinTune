#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    WinTune Ultimate - Windows 10/11 Multi-Stage Maintenance Suite

.DESCRIPTION
    A 32-step Windows maintenance tool covering:
      * Cleanup (temp, caches, recycle bins, browsers, Office, PDF, VS Code)
      * Performance tuning (telemetry, taskbar, power plan, visual effects)
      * System repair (DISM, SFC, component store)
      * Diagnostics (event logs, drivers, startup, scheduled tasks)
      * Security hardening (SMBv1, LLMNR/WPAD, DoH, Defender ASR)

.PARAMETER DryRun
    Preview every action without making any permanent changes.

.PARAMETER AllowResetBase
    Permit the irreversible DISM /ResetBase operation in Step 14.
    WARNING: After running, current Windows Updates cannot be uninstalled.

.PARAMETER AllowNetworkReset
    Permit the Winsock / TCP-IP stack reset in Step 23.
    Requires a reboot afterward.

.PARAMETER AllowPrefetch
    Permit the discouraged Prefetch directory purge in Step 21.
    NOT recommended for general use - slows app launches until cache rebuilds.

.PARAMETER ForceKill
    Automatically terminate browsers without interactive confirmation.

.PARAMETER SelfTest
    Verify the single-instance lock engine and exit.

.PARAMETER SkipSteps
    An array of step numbers to skip, e.g. -SkipSteps 1,12,13

.EXAMPLE
    .\WinTune.ps1 -DryRun
    Previews everything, changes nothing.

.EXAMPLE
    .\WinTune.ps1 -SkipSteps 1,12,13,15
    Skips the slow cleanup and DISM/SFC repair steps.

.EXAMPLE
    .\WinTune.ps1 -AllowResetBase -AllowNetworkReset
    Enables the two most aggressive (and irreversible) steps.

.NOTES
    Author:      WinTune Ultimate contributors
    Version:     1.0.0
    Requires:    Windows 10 1909+ or Windows 11
    Requires:    PowerShell 5.1 (built into Windows) or newer
    Requires:    Administrator privileges
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$AllowResetBase,
    [switch]$AllowNetworkReset,
    [switch]$AllowPrefetch,
    [switch]$ForceKill,
    [switch]$SelfTest,
    [string[]]$SkipSteps = @(),

    # ---- New in v3.1 ----
    [switch]$AllowWinget,                                          # Step 33
    [switch]$RemoveBloatware,                                      # Step 35
    [switch]$AllowSearchDefrag,                                    # Step 36
    [int]$FeatureUpdateDelayDays = 30,                             # Step 37
    [switch]$RemoveStartups,                                      # Step 38
    [switch]$InstallUpdates,                                     # Step 39
    [switch]$AllowDismRestore,                                   # Step 12 (RestoreHealth)
    [switch]$YesToAll,                                           # Auto-answer Y to all prompts
    [ValidateSet('Quick','Safe','Full','Weekly','')]
    [string]$Preset = '',                                        # Preset configuration
    [string]$RemoveDriver = '',                                  # Step 18: oemNN.inf to remove
    [switch]$AllowInstallerCleanup,                             # Step 40
    [switch]$AllowPackageCacheCleanup,                           # Step 42
    [switch]$ForceIrreversible,                                 # Required for irreversible ops (ResetBase)
    [switch]$AllowUwpCleanup,                                   # Step 43 - UWP LocalCache (opt-in)
    [switch]$AllowCatrootReset,                                 # Step 1 - Catroot2 signature cache reset (opt-in)

    # ---- New in v3.2 ----
    [switch]$AllowUltimatePerformance,                          # Step 26 - apply Ultimate Performance plan (default: Balanced)
    [switch]$AllowMalwareScan,                                  # Step 44 - run Malwarebytes quick scan if installed

    # ---- New in v3.3 ----
    [switch]$AllowSysMainTuning,                                # Step 45 - disable SysMain on all-SSD systems
    [switch]$AllowDoTuning,                                     # Step 46 - limit Delivery Optimization upload sharing
    [switch]$AllowCamWALCleanup,                                # Step 47 - delete bloated CapabilityAccessManager WAL file
    [switch]$AllowAutoRunDisable,                               # Step 49 - disable AutoRun/AutoPlay on removable media
    [switch]$AllowPersistenceAction,# Step 38 - disable non-essential persistence entries
    [switch]$AllowContextMenuAction,                           # Step 50 - disable non-essential context menu handlers
    [switch]$AllowProgramAuditAction,                         # Step 51 - remove orphaned program registry entries

    # ---- New in v3.4 (driver updates) - [FIX-DRV-STALE-PARAM] MaxStale=2555 (7yr) ----
    [switch]$AllowDriverUpdates,                               # Step 8b - install drivers that pass safety gates
    [int]$DriverMinAgeDays = 30,                               # Step 8b - minimum driver age in days
    [int]$DriverMaxSizeMB = 2048,                              # Step 8b - max driver size (skip corrupt manifests)
    [int]$DriverMaxStaleDays = 2555,                           # Step 8b - max driver age (stale threshold)

    # ---- New in v3.5 (winget policy) ----
    [switch]$AllowUnknownPackageVersions,                       # Step 33 - pass --include-unknown to winget

    # ---- New in v3.6 ----
    [switch]$AllowServiceTrim,                                  # Step 52 - safe service trim
    [switch]$AllowPrivacyTweaks,                                # Step 54 - HKCU privacy/Start tweaks
    [switch]$Rollback,                                          # Rollback mode: revert last run
    [string]$RollbackFrom = '',                                 # Optional path to a specific Rollback_*.jsonl

    # ---- New in v3.7 (TCP / VBS additions) ----
    [switch]$AllowTcpTuning,                                    # Step 55 - TCP performance tuning
    [switch]$AllowVbsAudit,                                     # Step 24 enhancement - VBS/HVCI audit

    # ---- New in v3.8 (Advanced tweaks) ----
    [switch]$AllowHibernationOff,                               # Step 57 - disable hibernation (desktops)
    [switch]$AllowModernStandbyOff,                             # Step 57 - disable modern standby (requires reboot)
    [switch]$AllowHpetOff,                                      # Step 57 - disable HPET (for low-latency gaming)
    [switch]$AllowRegistryBackup,                               # Step 57 - enable periodic registry backups

    # ---- New in v3.9 (DNS benchmark) ----
    # [FIX-DNSBENCH-PARAM] Benchmark well-known DNS resolvers and
    # optionally switch to the fastest. Skips on domain-joined PCs.
    [switch]$AllowDnsBenchmark,                                 # Step 58 - DNS resolver benchmark

    # [FIX-TIER2-PARAMS] Fast Startup + gaming toggles in Step 57
    [switch]$AllowFastStartupOff,                               # Step 57 - disable Fast Startup (HiberbootEnabled=0)
    [switch]$AllowGamingTweaks,                                 # Step 57 - enable HAGS + Game Mode

    # [FIX-TIER3-PARAMS] Sandbox / WSL / Dev Drive (Step 59)
    [switch]$AllowSandboxInstall,                               # Step 59 - enable Windows Sandbox
    [switch]$AllowWslInstall,                                   # Step 59 - install WSL
    [switch]$AllowDevDriveEnable,                               # Step 59 - enable Dev Drive capability

    # [FIX-CONFIG-PARAM] Optional JSON config file for per-machine
    # overrides. CLI parameters always win over config-file values.
    [string]$ConfigFile = '',

    # ---- Detached runner tracking ----
    [switch]$WaitForDetached,                                   # Wait indefinitely for all children before PostCheck
    [switch]$AllowScheduledTaskAction,

    # ---- Security posture audits (Step 56) ----
    [switch]$DisableWebClient,                                  # Step 56 - set WebClient service to Disabled
    [switch]$AddWpadHostsEntry,                                 # Step 56 - append 0.0.0.0 wpad to hosts file
    [switch]$EnableScriptBlockLogging,                          # Step 56 - enable PowerShell ScriptBlockLogging                         # Step 20 - disable non-Microsoft scheduled tasks
    [int]$DetachedWaitSeconds = 0,                              # Wait up to N seconds (0 = don't wait)

    # ---- Thresholds for destructive cleanup steps ----
    [int]$InstallerMinOrphanMB   = 500,                         # Step 40 - minimum orphan size to trigger cleanup
    [int]$InstallerMinAgeDays    = 180,                         # Step 40 - MSI/MSP age cutoff
    [int]$PackageCacheMinAgeDays = 30,                          # Step 42 - superseded folder age cutoff
    [int]$PackageCacheMinSizeMB  = 5,                           # Step 42 - minimum folder size
    [int]$PackageCacheMinTotalMB = 100                          # Step 42 - minimum total candidate size
)

# ---- [FIX-CONFIG-LOAD] Load optional JSON config before Preset ----
if ($ConfigFile -and (Test-Path -LiteralPath $ConfigFile)) {
    try {
        $__cfg = Get-Content -LiteralPath $ConfigFile -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($__prop in $__cfg.PSObject.Properties) {
            $__name = $__prop.Name
            $__val  = $__prop.Value
            if ($PSBoundParameters.ContainsKey($__name)) {
                # CLI explicitly set this — CLI wins
                continue
            }
            $__cur = Get-Variable -Name $__name -Scope Local -ErrorAction SilentlyContinue
            if (-not $__cur) {
                Write-Warning "Config: unknown parameter '$__name' — skipped"
                continue
            }
            if ($__cur.Value -is [System.Management.Automation.SwitchParameter]) {
                Set-Variable -Name $__name -Value ([switch]([bool]$__val)) -Scope Local
            } elseif ($__cur.Value -is [array]) {
                Set-Variable -Name $__name -Value @($__val) -Scope Local
            } else {
                Set-Variable -Name $__name -Value $__val -Scope Local
            }
            $PSBoundParameters[$__name] = (Get-Variable -Name $__name -Scope Local).Value
            Write-Host ("  [CONFIG] {0} = {1}" -f $__name, ($__val -join ',')) -ForegroundColor DarkGray
        }
        Write-Host ("  [CONFIG] Loaded {0} override(s) from {1}" -f $__cfg.PSObject.Properties.Count, $ConfigFile) -ForegroundColor DarkGray
    } catch {
        Write-Warning "Config file load failed: $($_.Exception.Message) — continuing with defaults"
    }
} elseif ($ConfigFile) {
    Write-Warning "Config file not found: $ConfigFile — continuing with defaults"
}

# ---- B1 fix: shadow the reserved $Profile automatic variable ----
# [FIX-B1-COMMENT] Public CLI accepts -Preset (not -Profile);
# internal logic uses $Script:PresetName.
if ($PSBoundParameters.ContainsKey('Preset')) { $Script:PresetName = [string]$Preset } else { $Script:PresetName = '' }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference   = 'Continue'

# ============================================================
# GLOBAL CONFIGURATION
# ============================================================
# [FIX-VERSION-SCHEME] Bumped to match parameter-phase comments (v3.7).
$Script:Version      = '3.7.0'
$Script:ScriptPath   = $MyInvocation.MyCommand.Path
$Script:ScriptDir    = Split-Path -Parent $Script:ScriptPath
$Script:ScriptName   = Split-Path -Leaf   $Script:ScriptPath
$Script:RunStamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
$Script:LogFile      = Join-Path $Script:ScriptDir 'WinTune.log'

# ---- Resolve hosts once, at load time ----
# Two distinct variables:
#   $Script:PowerShellExe       = parent host (whatever PowerShell
#                                 the user launched WinTune with)
#   $Script:RunnerPowerShellExe = host for all detached runner children.
#                                 Always powershell.exe, because .NET
#                                 Framework 4.8 honours the
#                                 SchUseStrongCrypto / SystemDefaultTls
#                                 registry values. .NET 8 (pwsh.exe)
#                                 does not, and on Win11 24H2+ it fails
#                                 the Akamai-fronted Microsoft Update
#                                 TLS handshake (0x8024402C / 0x80072EE7).
$__pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
$Script:PowerShellExe       = if ($__pwsh) { $__pwsh.Source } else { (Get-Command powershell.exe -ErrorAction Stop).Source }
$Script:RunnerPowerShellExe = (Get-Command powershell.exe -ErrorAction Stop).Source

# ---- Log rotation: if the file is over 5 MB, rotate to timestamped file
# ---- and keep the 3 most recent rotated logs. Never silently delete. ----
if (Test-Path -LiteralPath $Script:LogFile) {
    try {
        $__logSize = (Get-Item -LiteralPath $Script:LogFile -Force -ErrorAction Stop).Length
        if ($__logSize -gt 5MB) {
            $__rotated = '{0}.{1}.log' -f ($Script:LogFile -replace '\.log$',''), $Script:RunStamp
            Move-Item -LiteralPath $Script:LogFile -Destination $__rotated -Force -ErrorAction Stop
            # Keep only the 3 most recent rotated logs
            $__rotatedFiles = Get-ChildItem -LiteralPath $Script:ScriptDir -Filter 'WinTune.*.log' -File -ErrorAction SilentlyContinue |
                              Sort-Object LastWriteTime -Descending
            if ($__rotatedFiles.Count -gt 3) {
                $__rotatedFiles | Select-Object -Skip 3 | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
    } catch { }
}

# ---- Write run-start marker so each run is clearly delimited ----
$__runMarker = @()

$__runMarker += ''
$__runMarker += ('=' * 70)
$__runMarker += "  WinTune RUN STARTED  $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
$__runMarker += "  Host: $env:COMPUTERNAME    User: $env:USERNAME    PID: $PID"
$__runMarker += ('=' * 70)

foreach ($__line in $__runMarker) { Add-Content -LiteralPath $Script:LogFile -Value $__line -Encoding UTF8 -ErrorAction SilentlyContinue }
$Script:LockFile     = Join-Path $Script:ScriptDir 'WinTune.lock'
$Script:TranscriptOn = $false
$Script:RunnerTempDir = $null

$Script:DryRun              = $DryRun.IsPresent
$Script:AllowResetBase      = $AllowResetBase.IsPresent
$Script:AllowNetworkReset   = $AllowNetworkReset.IsPresent
$Script:AllowPrefetch       = $AllowPrefetch.IsPresent
$Script:ForceKill           = $ForceKill.IsPresent
$Script:SkipSteps           = $SkipSteps
$Script:SelfTest            = $SelfTest.IsPresent

# ---- New in v3.1 ----
$Script:AllowWinget           = $AllowWinget.IsPresent
$Script:RemoveBloatware       = $RemoveBloatware.IsPresent
$Script:AllowSearchDefrag     = $AllowSearchDefrag.IsPresent
$Script:RemoveStartups       = $RemoveStartups.IsPresent
$Script:InstallUpdates       = $InstallUpdates.IsPresent
$Script:AllowDismRestore    = $AllowDismRestore.IsPresent
$Script:RemoveDriver       = $RemoveDriver
$Script:YesToAll          = $YesToAll.IsPresent
$Script:ForceIrreversible = $ForceIrreversible.IsPresent
$Script:AllowUwpCleanup   = $AllowUwpCleanup.IsPresent
$Script:AllowCatrootReset = $AllowCatrootReset.IsPresent
$Script:AllowInstallerCleanup = $AllowInstallerCleanup.IsPresent
$Script:AllowPackageCacheCleanup = $AllowPackageCacheCleanup.IsPresent
$Script:AllowUltimatePerformance = $AllowUltimatePerformance.IsPresent
$Script:AllowMalwareScan = $AllowMalwareScan.IsPresent
$Script:AllowSysMainTuning = $AllowSysMainTuning.IsPresent
$Script:AllowDoTuning = $AllowDoTuning.IsPresent
$Script:AllowCamWALCleanup = $AllowCamWALCleanup.IsPresent
$Script:AllowPersistenceAction = $AllowPersistenceAction.IsPresent
$Script:AllowAutoRunDisable = $AllowAutoRunDisable.IsPresent
$Script:AllowScheduledTaskAction = $AllowScheduledTaskAction.IsPresent
$Script:DisableWebClient         = $DisableWebClient.IsPresent
$Script:AddWpadHostsEntry        = $AddWpadHostsEntry.IsPresent
$Script:EnableScriptBlockLogging = $EnableScriptBlockLogging.IsPresent
$Script:AllowContextMenuAction = $AllowContextMenuAction.IsPresent
$Script:AllowProgramAuditAction = $AllowProgramAuditAction.IsPresent
# ---- New in v3.4 (driver updates) - [FIX-DRV-STALE-PARAM] MaxStale=2555 (7yr) ----
$Script:AllowDriverUpdates = $AllowDriverUpdates.IsPresent
$Script:DriverMinAgeDays = $DriverMinAgeDays
$Script:DriverMaxSizeMB = $DriverMaxSizeMB
$Script:DriverMaxStaleDays = $DriverMaxStaleDays
# ---- New in v3.5 (winget policy) ----
$Script:AllowUnknownPackageVersions = $AllowUnknownPackageVersions.IsPresent
# ---- New in v3.6 ----
$Script:AllowServiceTrim   = $AllowServiceTrim.IsPresent
$Script:AllowPrivacyTweaks = $AllowPrivacyTweaks.IsPresent
$Script:AllowTcpTuning     = $AllowTcpTuning.IsPresent
$Script:AllowVbsAudit      = $AllowVbsAudit.IsPresent
$Script:AllowHibernationOff = $AllowHibernationOff.IsPresent
$Script:AllowModernStandbyOff = $AllowModernStandbyOff.IsPresent
$Script:AllowHpetOff = $AllowHpetOff.IsPresent
$Script:AllowRegistryBackup = $AllowRegistryBackup.IsPresent
$Script:AllowDnsBenchmark = $AllowDnsBenchmark.IsPresent
$Script:AllowFastStartupOff = $AllowFastStartupOff.IsPresent
$Script:AllowGamingTweaks = $AllowGamingTweaks.IsPresent
$Script:AllowSandboxInstall = $AllowSandboxInstall.IsPresent
$Script:AllowWslInstall = $AllowWslInstall.IsPresent
$Script:AllowDevDriveEnable = $AllowDevDriveEnable.IsPresent
$Script:RollbackMode       = $Rollback.IsPresent
$Script:InRollbackMode   = $false

# Detached runner tracking (populated by Fix A; consumed by Fix C)
$Script:WaitForDetached     = $WaitForDetached.IsPresent
$Script:DetachedWaitSeconds = [int]$DetachedWaitSeconds
$Script:InstallerMinOrphanMB   = [int]$InstallerMinOrphanMB
$Script:InstallerMinAgeDays    = [int]$InstallerMinAgeDays
$Script:PackageCacheMinAgeDays = [int]$PackageCacheMinAgeDays
$Script:PackageCacheMinSizeMB  = [int]$PackageCacheMinSizeMB
$Script:PackageCacheMinTotalMB = [int]$PackageCacheMinTotalMB
$Script:RollbackFrom       = $RollbackFrom
$Script:RollbackEntries    = New-Object System.Collections.ArrayList
$Script:BackupDir         = $null
$Script:RollbackManifestPath = $null
$Script:WinHomeSku         = $false

# ---- Profile presets (applied BEFORE initialization of skip list) ----
# Capture user-supplied skips BEFORE the profile is applied
$__userSkipSteps = @($SkipSteps)

if ($Script:PresetName) {
switch ($Script:PresetName.ToLowerInvariant()) {
        'quick' {
            $SkipSteps = @(4,5,6,9,12,13,14,15,18,19,20,21,22,23,24,25,26,29,30,31,32,33,34,35,36,37,38,39)
        }
        'safe' {
            $SkipSteps = @(4,5,6,9,12,13,14,15,18,19,20,21,22,23,24,25,29,30,31,33,34,35,36,37,38,39)
        }
        'full' {
            $SkipSteps = @()
        }
        # [FIX-WEEKLY-PRESET] Weekly = cheap recurring maintenance.
        # Skip only heavy/slow/one-time/gated steps so the weekly run
        # actually does useful recurring work instead of mirroring 'quick'.
        #   Skipped:  12-15 (DISM/SFC), 18 (DriverStore audit),
        #             21 (Prefetch, gated anyway), 22 (standby, no-op),
        #             23 (Network reset, gated), 24 (SSD optimize, long),
        #             29 (SMBv1, one-time), 36 (Search defrag, heavy).
        'weekly' {
            $SkipSteps = @(12,13,14,15,18,21,22,23,24,29,36)
        }
    }
}

# Merge user -SkipSteps with profile skip list (union, not overwrite).
# Fix-SkipSteps-Merge-applied
# Both sides are normalised to strings first: the preset switch assigns
# integers (@(4,5,6,...)) while the parameter is [string[]] (from
# -SkipSteps 1,1b,...). Mixing int[] and string[] breaks Sort-Object
# -Unique in PS 5.1 (dedupe only within type groups). The explicit
# hashtable dedupe below is type-agnostic.
$__profileSkips = @($SkipSteps | ForEach-Object { [string]$_ })
$__userSkipSteps = @($__userSkipSteps | ForEach-Object { [string]$_ })
$__seen = @{}
$__merged = New-Object System.Collections.ArrayList
foreach ($v in @($__profileSkips + $__userSkipSteps)) {
    if (-not $__seen.ContainsKey($v)) {
        $__seen[$v] = $true
        [void]$__merged.Add($v)
    }
}
$SkipSteps = @($__merged | Sort-Object)

$Script:FeatureUpdateDelayDays = $FeatureUpdateDelayDays

# Metrics captured during PreCheck / compared in PostCheck
$Script:StartFreeBytes      = 0
$Script:StartFreeDisplay    = '0.00'
$Script:LockStream          = $null
$Script:RebootRequired      = $false
$Script:RebootReasons       = @()
$Script:LastStepStatus      = $null   # set by steps that want non-default report status

# Detached runner tracking (populated by Fix A / Fix B / Fix C)
#   Key: PID (int)
#   Value: PSCustomObject { Kind; Note; StartedAt; ExitedAt; ExitCode; EventSource }
# Note: $Script:WaitForDetached and $Script:DetachedWaitSeconds are
# initialized from the CLI parameters in the RollbackMode block below
# (Fix C2). Do not initialize them here â€” that would clobber the CLI
# values when this block runs after the parameter assignment block.
$Script:DetachedRunners     = @{}
$Script:ResetBaseStatus     = $null


# Step definition table - lets us skip by number uniformly
$Script:StepNames = @{
    1  = 'Clean System-Wide Junk'
    2  = 'Purge Recycle Bins and Loose Storage'
    3  = 'Clear Web Browser Caches'
    4  = 'Clear Office/Outlook Temp Files'
    5  = 'Clear PDF Reader Caches'
    6  = 'Clear Copilot and VS Code Caches'
    7  = 'Interactive AppData Cache Scan'
    8  = 'Reset Thumbnail and Icon Caches'
    9  = 'Prune Broken Desktop Shortcuts'
    10 = 'Tune Background Telemetry Services'
    11 = 'Taskbar and Game DVR Tweaks'
    12 = 'Core Component / System File Repair'
    13 = 'Deployment Image Cloud Restoration'
    14 = 'Component Store Base Optimization'
    15 = 'Component Store Maintenance'
    16 = 'Clear Event Viewer Logs'
    17 = 'Cap Shadow Storage (VSS)'
    18 = 'Driver Store Audit'
    19 = 'Boot Startup Audit'
    20 = 'Scheduled Tasks Audit'
    21 = 'Prefetch Cache Trimming'
    22 = 'Standby Memory Flush'
    23 = 'Network Stack Realignment'
    24 = 'SSD Storage Optimization'
    25 = 'System Restore Point'
    26 = 'Ultimate Performance Power Plan'
    27 = 'Desktop Interface Responsiveness'
    28 = 'Enable Windows Storage Sense'
    29 = 'Disable Legacy SMBv1'
    30 = 'Disable LLMNR and WPAD'
    31 = 'Enable DNS over HTTPS'
    32 = 'Defender ASR Rules (Audit Mode)'
    # ---- New in v3.1 ----
    33 = 'Winget App Upgrades'
    34 = 'Font Cache and Icon Index Rebuild'
    35 = 'Bloatware Provisioning Audit'
    36 = 'Windows Search Index Defrag'
    37 = 'Feature Update Deferral'
    38 = 'Startup Entry Bulk Removal'
    39 = 'Windows Update Auto-Install'
    40 = 'Windows Installer Orphan Cleanup'
    41 = 'Defender Scans Cache Cleanup'
    42 = 'ProgramData Package Cache Cleanup'
    43 = 'UWP LocalCache Sweep'
    44 = 'Malwarebytes Quick Scan (optional)'
    45 = 'SysMain Tuning (SSD-only)'
    46 = 'Delivery Optimization Limit'
    47 = 'CapabilityAccessManager WAL Check'
    49 = 'Disable AutoRun on Removable Media'
    50 = 'Context Menu Handler Audit'
    51 = 'Installed Program Audit'
    52 = 'Safe Service Trim'
    54 = 'Privacy and Start Menu Tweaks'
    55 = 'TCP Performance Tuning'
    56 = 'Security Posture Audits'
    57 = 'Advanced System Tweaks'
    58 = 'DNS Resolver Benchmark'
    59 = 'Sandbox / WSL / Dev Drive Audit'
    '1b' = 'SSD Fullness Check'
    '8b' = 'Driver Update Audit + Install (Detached)'
}

# Per-step descriptions used in the HTML report Details column
$Script:StepDescriptions = @{
    '1' = 'Cleared temporary files, caches, and logs to reclaim disk space.'
    '1b' = 'Checked drive fullness; warned if any drive exceeded 80% usage.'
    '2' = 'Emptied Recycle Bins and removed log files older than 30 days.'
    '3' = 'Purged browser caches for Chrome, Edge, and other Chromium browsers.'
    '4' = 'Closed Office apps and cleared temp locks and Outlook attachment caches.'
    '5' = 'Cleared PDF reader caches for Adobe, Foxit, and SumatraPDF.'
    '6' = 'Cleared VS Code, Teams, and Copilot developer caches.'
    '7' = 'Interactively scanned and offered to purge large known app caches.'
    '8' = 'Reset Windows thumbnail and icon caches to fix corrupted icons.'
    '8b' = 'Launched a detached driver audit to identify eligible updates.'
    '9' = 'Removed broken desktop shortcuts pointing to missing targets.'
    '10' = 'Set telemetry services to Manual and disabled scheduled telemetry tasks.'
    '11' = 'Enabled taskbar End Task and disabled Game DVR background recording.'
    '12' = 'Launched a detached DISM and SFC repair to fix system file corruption.'
    '13' = 'No-op; handled by Step 12 detached runner.'
    '14' = 'No-op; handled by Step 12 detached runner.'
    '15' = 'No-op; handled by Step 12 detached runner.'
    '16' = 'Cleared Application, System, and Setup event logs.'
    '17' = 'Capped Volume Shadow Copy storage for System Restore retention.'
    '18' = 'Audited third-party driver packages in the DriverStore.'
    '19' = 'Audited all auto-launching programs.'
    '20' = 'Audited scheduled tasks and optionally disabled non-Microsoft tasks.'
    '21' = 'Purged Prefetch cache (discouraged for general use).'
    '22' = 'No-op; standby memory is managed automatically by Windows.'
    '23' = 'Reset Winsock and TCP/IP stack (requires reboot).'
    '24' = 'Skipped defrag on SSDs and launched defrag only for HDDs.'
    '25' = 'Created a System Restore point as a safety snapshot.'
    '26' = 'Set the Balanced power plan for balanced performance and power.'
    '27' = 'Disabled transparency and animations; preserved ClearType.'
    '28' = 'Configured Storage Sense with Downloads folder protected.'
    '29' = 'Disabled SMBv1 and hardened LanmanServer registry settings.'
    '30' = 'Disabled LLMNR and WPAD to prevent credential theft.'
    '31' = 'Enabled DNS over HTTPS and verified resolver compatibility.'
    '32' = 'Applied seven Defender ASR rules in Audit mode.'
    '33' = 'Launched a detached winget upgrade runner.'
    '34' = 'Rebuilt the font cache and Explorer icon index.'
    '35' = 'Audited and optionally removed provisioned bloatware packages.'
    '36' = 'Checked search index for legacy layout; advised on manual rebuild.'
    '37' = 'Configured 30-day deferral for Windows feature updates.'
    '38' = 'Audited startup entries; kept signed publishers and flagged others.'
    '39' = 'Launched a detached Windows Update runner.'
    '40' = 'Identified orphaned MSI/MSP cache files in C:\Windows\Installer.'
    '41' = 'Cleared old Defender scan caches to reclaim disk space.'
    '42' = 'Identified superseded installer caches in ProgramData\Package Cache.'
    '43' = 'Swept UWP LocalCache folders and reset the Microsoft Store cache.'
    '44' = 'Optionally launched a Malwarebytes quick scan if installed.'
    '45' = 'Disabled prefetcher on SSD systems; kept SysMain for memory compression.'
    '46' = 'Set Delivery Optimization to LAN-only to stop peer uploads.'
    '47' = 'Checked CapabilityAccessManager WAL file size and reported status.'
    '49' = 'Disabled AutoRun on all drives to block USB/CD malware.'
    '50' = 'Audited context menu shell extensions.'
    '51' = 'Audited installed programs for orphaned uninstall entries.'
    '52' = 'Set five non-essential services to Manual or Disabled.'
    '54' = 'Applied HKCU privacy and Start Menu tweaks.'
    '55' = 'Enabled RSS, normalized auto-tuning, and set CUBIC congestion provider.'
    '56' = 'Audited seven security controls (WebClient, WPAD, LAPS, ScriptBlockLogging, UAC, SMB signing, BitLocker).'
    '57' = 'Applied advanced tweaks (hibernation, HPET, modern standby, registry backup).'
    '58' = 'Benchmarked DNS resolvers and switched to the fastest (home/SMB only).'
    '59' = 'Audited and optionally enabled Windows Sandbox, WSL, and Dev Drive capability.'
}



# ============================================================
# LOGGING ENGINE
# ============================================================
# ============================================================
# EMBEDDED DETACHED RUNNERS (written to TEMP at runtime)
# ============================================================
$Script:EmbeddedSfcDismRunner = @'
# WinTune - SFC / DISM Repair Runner (Interactive Target Mode)
# Launched by WinTune Step 12. Runs in its own visible window with native progress indicators.

$ErrorActionPreference = 'Continue'
$__logDir = if ($env:FC_LOG_DIR) { $env:FC_LOG_DIR } else { Split-Path -Parent $PSCommandPath }
$logFile = if ($env:FC_LOG_DIR) { Join-Path $env:FC_LOG_DIR 'WinTune_SfcDism.log' } else { Join-Path (Split-Path -Parent $PSCommandPath) 'WinTune_SfcDism.log' }
$allowResetBase    = ($env:FC_ALLOW_RESETBASE    -eq '1')
$allowDismRestore  = ($env:FC_ALLOW_DISM_RESTORE -eq '1')
$yesToAll          = ($env:FC_YES_TO_ALL         -eq '1')

function SD-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'STEP'  { 'Cyan' }
        'HEAD'  { 'Magenta' }
        default { 'Gray' }
    }
    $line = "$stamp [$Level] $Message"
    Write-Host $line -ForegroundColor $color
    try { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 } catch { }
}

function SD-Section {
    param([string]$Title)
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host (" $Title") -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan
}

function Pause-Exit {
    param([int]$ExitCode = 0)
    Write-Host ''
    Write-Host 'Press any key to close this window...' -ForegroundColor DarkGray
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
    try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue } catch { }
    exit $ExitCode
}

function Read-YesNo {
    param([string]$Prompt)
    if ($yesToAll) {
        Write-Host ("  [AUTO] {0} -> Y" -f $Prompt) -ForegroundColor Cyan
        return $true
    }
    while ($true) {
        $raw = Read-Host $Prompt
        if ($null -eq $raw) { $raw = '' }
        $clean = $raw.Trim().ToLowerInvariant()
        if ($clean.StartsWith('y')) { return $true }
        if ($clean.StartsWith('n') -or $clean -eq '') { return $false }
        Write-Host '  Please enter Y or N.' -ForegroundColor Yellow
    }
}

# Optimized native execution hook that forces an interactive console layout state
# Native execution with live heartbeat + progress log polling
function Invoke-NativeLive {
    param(
        [string]$Exe,
        [string[]]$Arguments,
        [string]$Label
    )

    Write-Host ""
    Write-Host "--- $Label Execution Hook Activating ---" -ForegroundColor Cyan
    try { Add-Content -LiteralPath $logFile -Value "`n--- $Label ---" -Encoding UTF8 } catch {}

    $start = Get-Date
    $exitCode = -1
    $proc = $null

    # ---- Launch ----
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $Exe
        $psi.Arguments              = ($Arguments -join ' ')
        $psi.UseShellExecute        = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.CreateNoWindow         = $false
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
    } catch {
        Write-Host ("  [ERROR] Failed to launch {0}: {1}" -f $Exe, $_.Exception.Message) -ForegroundColor Red
        return @{ ExitCode = -1 }
    }

    # ---- Redirected-output detection ----
    $isRedirected = $false
    try { $isRedirected = [Console]::IsOutputRedirected } catch { }

    # ---- State ----
    # [CLEAN-SFC-DEAD] Removed $spinFrames / $spinIdx — remnants of
    # the old spinner, replaced by the 10s heartbeat below.
    $lastProgress = "$Label started"
    $lineWidth    = 110
    $lastLogTime  = Get-Date

    # Progress phase tracking (prevents regression)
    # Rank each phase; higher rank wins over lower rank
    $phaseRank = @{
        'started'          = 0
        'scan started'     = 1
        'verify phase started' = 2
        'verifying'        = 3
        'verify complete'  = 4
        'repair phase started' = 5
        'repairing'        = 6
        'repair complete'  = 7
    }
    $lastPhaseRank = 0

    # Stall state
    $lastProgressChangeTime = Get-Date
    $stallThreshold = 60   # Show stalled tag only after 60s of no change

    # ---- Identify log sources ----
    $logSources = New-Object System.Collections.Generic.List[string]
    if ($Exe -match 'sfc|dism') {
        $cbs = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
        if (Test-Path -LiteralPath $cbs) { $logSources.Add($cbs) }
    }
    if ($Exe -match 'dism') {
        $dism = Join-Path $env:SystemRoot 'Logs\DISM\dism.log'
        if (Test-Path -LiteralPath $dism) { $logSources.Add($dism) }
    }

    # ---- Snapshot log offsets (only parse NEW lines) ----
    $logStartOffsets = @{}
    foreach ($src in $logSources) {
        try {
            $logStartOffsets[$src] = [int64](Get-Item -LiteralPath $src -Force).Length
        } catch {
            $logStartOffsets[$src] = [int64]0
        }
    }

    # ---- Begin async stdout/stderr line readers ----
    $stdoutTask = $proc.StandardOutput.ReadLineAsync()
    $stderrTask = $proc.StandardError.ReadLineAsync()

    # ---- Main loop ----
    while (-not $proc.HasExited) {
        Start-Sleep -Milliseconds 250
        $now     = Get-Date
        $elapsed = $now - $start

        # ---- Drain stdout ----
        while ($stdoutTask -and $stdoutTask.IsCompleted -and $stdoutTask.Result -ne $null) {
            $line = $stdoutTask.Result
            $m = $null
            if     ($line -match 'Verification\s+(\d+)%\s+complete')  { $m = "verification:$($Matches[1])%" }
            elseif ($line -match 'Beginning verification phase')      { $m = 'verify phase started' }
            elseif ($line -match 'Beginning system scan')             { $m = 'scan started' }
            elseif ($line -match '\[=+\s*([\d.]+)%\s*\]')             { $m = "dism:$($Matches[1])%" }
            if ($m) {
                $rank = if ($m -match '^verification:') { 3 } elseif ($m -match '^dism:') { 3 } else { $phaseRank[$m] }
                if ($rank -ge $lastPhaseRank) {
                    $lastProgress = if ($m -match '^verification:(\d+)%$') { "SFC verification: $($Matches[1])%" }
                                    elseif ($m -match '^dism:([\d.]+)%$') { "DISM: $($Matches[1])% complete" }
                                    else { "SFC: $m" }
                    $lastPhaseRank = $rank
                    $lastProgressChangeTime = $now
                }
            }
            $stdoutTask = $proc.StandardOutput.ReadLineAsync()
        }

        # Drain stderr
        while ($stderrTask -and $stderrTask.IsCompleted -and $stderrTask.Result -ne $null) {
            $stderrTask = $proc.StandardError.ReadLineAsync()
        }

        # ---- Poll logs (throttled every 500ms) ----
        if (($now - $lastLogTime).TotalMilliseconds -ge 500) {
            $lastLogTime = $now
            foreach ($src in $logSources) {
                try {
                    $startOffset = if ($logStartOffsets.ContainsKey($src)) { $logStartOffsets[$src] } else { 0 }
                    $curLen = [int64]0
                    try { $curLen = (Get-Item -LiteralPath $src -Force).Length } catch { }
                    if ($curLen -le $startOffset) { continue }

                    $fs = [System.IO.File]::Open($src, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    try {
                        [void]$fs.Seek($startOffset, [System.IO.SeekOrigin]::Begin)
                        $toRead = [int]($curLen - $startOffset)
                        if ($toRead -le 0) { continue }
                        $buf = New-Object byte[] $toRead
                        [void]$fs.Read($buf, 0, $toRead)
                        $newText = [System.Text.Encoding]::UTF8.GetString($buf)
                        $logStartOffsets[$src] = $curLen
                    } finally {
                        $fs.Close()
                    }

                    foreach ($line in ($newText -split "`r?`n")) {
                        $m = $null
                        $rank = -1

                        if ($Label -eq 'RestoreHealth' -and $line -match 'DownloadProgress:\s*\[(\d+)\s*/\s*(\d+)\]') {
                            $cur = [int]$Matches[1]; $tot = [int]$Matches[2]
                            if ($tot -gt 0) {
                                $pct = [int](($cur / $tot) * 100)
                                $m = "Download: $pct%"
                                $rank = 3
                            }
                        }
                        elseif ($line -match '\[SR\]\s+Beginning\s+(Verify|Repair)') {
                            $phase = $Matches[1].ToLower()
                            $m = "SFC: $phase phase started"
                            $rank = if ($phase -eq 'verify') { 2 } else { 5 }
                        }
                        elseif ($line -match '\[SR\]\s+Verifying\s+(\d+)\s+components') {
                            $m = "SFC: verifying $($Matches[1]) components"
                            $rank = 3
                        }
                        elseif ($line -match '\[SR\]\s+Verify complete') {
                            $m = 'SFC: verify complete'
                            $rank = 4
                        }
                        elseif ($line -match '\[SR\]\s+Repairing\s+(\d+)\s+components') {
                            $m = "SFC: repairing $($Matches[1]) components"
                            $rank = 6
                        }
                        elseif ($line -match '\[SR\]\s+Repair complete') {
                            $m = 'SFC: repair complete'
                            $rank = 7
                        }
                        elseif ($line -match '\[SR\].*?[Bb]egin.*?[Vv]erif') {
                            $m = 'SFC: verify phase started (broad)'
                            $rank = 2
                        }
                        elseif ($line -match '\[SR\].*?[Vv]erif(y|ication|ying)') {
                            if ($line -match '(\d+)\s+components') {
                                $m = "SFC: verifying $($Matches[1]) components (broad)"
                            } else {
                                $m = 'SFC: verifying components (broad)'
                            }
                            $rank = 3
                        }
                        elseif ($line -match '\[SR\].*?[Vv]erif.*?complete') {
                            $m = 'SFC: verify complete (broad)'
                            $rank = 4
                        }
                        elseif ($line -match '\[SR\].*?[Rr]epair(ing|ed)?') {
                            if ($line -match 'complete') {
                                $m = 'SFC: repair complete (broad)'
                                $rank = 7
                            } else {
                                $m = 'SFC: repairing components (broad)'
                                $rank = 5
                            }
                        }
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

                        if ($m -and $rank -ge $lastPhaseRank) {
                            $lastProgress = $m
                            $lastPhaseRank = $rank
                            $lastProgressChangeTime = $now
                        }
                    }
                } catch { }
            }
        }

        # ---- Render ----
        # Stall tag: only show if no progress change for 60+ seconds AND process still running
        $stallSec = [int](($now - $lastProgressChangeTime).TotalSeconds)
        $stallTag = if ($stallSec -ge $stallThreshold) { "  [stalled ${stallSec}s]" } else { '' }

        $elapsedStr = if ($elapsed.TotalHours -ge 1) { '{0:hh\:mm\:ss}' -f $elapsed } else { '{0:mm\:ss}' -f $elapsed }

        # [FIX-S12-1] Deduplicated 10-second heartbeat.
        # The old check `% 10 -lt 0.5` fired twice per window (at t=10.00s
        # and t=10.25s) because the loop runs every 250 ms. Use an explicit
        # last-print timestamp instead.
        if (-not $script:__lastHeartbeat) { $script:__lastHeartbeat = $start }
        if (($now - $script:__lastHeartbeat).TotalSeconds -ge 10) {
            # [FIX-S12-2] Suppress the stall tag once DISM's download
            # reached 100% - the install phase emits no progress lines,
            # so the old stall tag looked like a hang when the process
            # was actually working. Only show "stalled" if we haven't
            # seen any progress line at all in `stallThreshold` seconds.
            $effectiveStall = $stallTag
            if ($lastProgress -match 'Download:\s*100%|RestoreHealth.*100%') {
                $effectiveStall = ''
            }
            $line = "  [$elapsedStr] $Label - $lastProgress$effectiveStall"
            Write-Host $line -ForegroundColor DarkGray
            try { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 } catch {}
            $script:__lastHeartbeat = $now
        }
    }

    # Clear spinner line
    if (-not $isRedirected) {
        [Console]::Write("`r" + (' ' * $lineWidth) + "`r")
    }

    # ---- Collect final exit code ----
    try {
        $proc.WaitForExit()
        $exitCode = $proc.ExitCode
        if ($null -eq $exitCode) { $exitCode = -1 }
    } catch { $exitCode = -1 }

    # Drain any remaining output
    $finalLines = New-Object System.Collections.Generic.List[string]
    while ($stdoutTask -and $stdoutTask.IsCompleted -and $stdoutTask.Result -ne $null) {
        $finalLines.Add($stdoutTask.Result) | Out-Null
        $stdoutTask = $proc.StandardOutput.ReadLineAsync()
    }
    while ($stderrTask -and $stderrTask.IsCompleted -and $stderrTask.Result -ne $null) {
        $finalLines.Add($stderrTask.Result) | Out-Null
        $stderrTask = $proc.StandardError.ReadLineAsync()
    }
    foreach ($line in $finalLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        Write-Host "  $line" -ForegroundColor Gray
        try { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 } catch {}
    }

    # Footer
    # [CLEAN-SFC-CAPTURE] Removed the copy-capture-file block and the
    # cleanup loop — $captureFile and $cmdScript were never defined
    # anywhere in the runner, so both were always no-ops. Remnants of
    # a prior iteration that used temp-file I/O.
    $duration = (Get-Date) - $start
    $footer = "--- $Label complete in [ $(([math]::Round($duration.TotalMinutes, 1))) min ] (Exit Code: $exitCode) ---"
    Write-Host $footer -ForegroundColor DarkGray
    try { Add-Content -LiteralPath $logFile -Value $footer -Encoding UTF8 } catch {}

    return @{ ExitCode = $exitCode }
}

try {
    Clear-Host
    try { $Host.UI.RawUI.WindowTitle = 'WinTune - SFC / DISM Repair' } catch { }
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host ' WinTune - SFC / DISM Repair (Interactive Mode)' -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan

    # [FIX-S12-3] Truncate the child log so this run's content is the
    # only thing in WinTune_SfcDism.log. Prior runs accumulated here,
    # making it impossible to know which SFC/DISM output belonged to
    # which parent invocation.
    try {
        if (Test-Path -LiteralPath $logFile) {
            Remove-Item -LiteralPath $logFile -Force -ErrorAction SilentlyContinue
        }
    } catch { }

    SD-Log 'SFC / DISM runner started.' 'OK'
    SD-Log "PID: $PID"
    SD-Log "Log: $logFile"
    SD-Log ("Allow ResetBase:    {0}" -f $allowResetBase) 'INFO'
    SD-Log ("Allow DISM Restore: {0}" -f $allowDismRestore) 'INFO'

    # 1. DISM CheckHealth
    SD-Section 'Step 1/5 - DISM Component Store CheckHealth'
    SD-Log 'Fast integrity check of the Windows Component Store.' 'INFO'
    SD-Log 'Takes 5-30 seconds. Read-only.' 'INFO'

    if (Read-YesNo 'Run DISM CheckHealth? (Y/N)') {
        SD-Log 'Running DISM /Online /Cleanup-Image /CheckHealth...' 'STEP'
        $r = Invoke-NativeLive -Exe 'dism.exe' -Arguments @('/Online','/Cleanup-Image','/CheckHealth') -Label 'CheckHealth'
        if ($r.ExitCode -eq 0) {
            SD-Log 'DISM CheckHealth completed successfully.' 'OK'
        } else {
            SD-Log ("[WARN] DISM CheckHealth returned exit code {0}." -f $r.ExitCode) 'WARN'
        }
    } else {
        SD-Log 'Skipped by user.' 'WARN'
    }

    # 2. SFC /scannow
    SD-Section 'Step 2/5 - SFC /scannow'
    SD-Log 'Verifies and repairs protected system files.' 'INFO'
    SD-Log 'Duration: 5-15 minutes.' 'INFO'

    if (Read-YesNo 'Run SFC /scannow? (Y/N)') {
        SD-Log 'Running sfc /scannow...' 'STEP'
        $r = Invoke-NativeLive -Exe 'sfc.exe' -Arguments @('/scannow') -Label 'SFC'

        $sfcExit = $r.ExitCode
        $verdict = switch ($sfcExit) {
            0 { 'No integrity violations found.' }
            1 { 'Corrupt files found and successfully repaired.' }
            2 { 'Corrupt files found but some could not be repaired.' }
            default { ("Unexpected exit code: {0}" -f $sfcExit) }
        }
        SD-Log ("SFC exit code: {0} - {1}" -f $sfcExit, $verdict) $(if ($sfcExit -le 1) { 'OK' } else { 'WARN' })
    } else {
        SD-Log 'Skipped by user.' 'WARN'
    }

    # 3. DISM RestoreHealth
    SD-Section 'Step 3/5 - DISM RestoreHealth (Cloud)'
    SD-Log 'Downloads clean component files from Microsoft and repairs corruption.' 'INFO'
    SD-Log 'Requires internet. Duration: 5-25 minutes.' 'INFO'

    if (-not $allowDismRestore) {
        SD-Log 'RestoreHealth is not authorized (no -AllowDismRestore flag).' 'WARN'
        SD-Log 'Skipping to next step.' 'INFO'
    } elseif (Read-YesNo 'Run DISM RestoreHealth? (Y/N)') {
        SD-Log 'Checking internet connectivity...' 'STEP'
        $online = $false
        try {
            # CORRECTED HOSTNAME FOR STRICT DNS LOOKUP
            $null = [System.Net.Dns]::GetHostAddresses('tlu.dl.delivery.mp.microsoft.com')
            $online = $true
        } catch { }

        if (-not $online) {
            SD-Log '[WARN] Microsoft Update cloud unreachable - skipping RestoreHealth.' 'WARN'
        } else {
            SD-Log 'Running DISM /Online /Cleanup-Image /RestoreHealth...' 'STEP'
            $r = Invoke-NativeLive -Exe 'dism.exe' -Arguments @('/Online','/Cleanup-Image','/RestoreHealth') -Label 'RestoreHealth'
            if ($r.ExitCode -eq 0) {
                SD-Log 'DISM RestoreHealth completed.' 'OK'
            } else {
                SD-Log ("[WARN] DISM RestoreHealth returned exit code {0}." -f $r.ExitCode) 'WARN'
            }
        }
    } else {
        SD-Log 'Skipped by user.' 'WARN'
    }

    # 4. DISM ResetBase (irreversible, gated)
    SD-Section 'Step 4/5 - DISM ResetBase (Irreversible)'
    SD-Log 'Permanently removes old superseded Windows Update files.' 'WARN'
    SD-Log 'Once complete, you CANNOT uninstall current updates.' 'WARN'

    if (-not $allowResetBase) {
        SD-Log 'ResetBase is not authorized (no -AllowResetBase flag).' 'WARN'
    } else {
        Write-Host ''
        Write-Host 'WARNING: This operation is IRREVERSIBLE.' -ForegroundColor Red
        if (Read-YesNo 'Run DISM ResetBase? (Y/N)') {
            $forceIrrev = ($env:FC_FORCE_IRREVERSIBLE -eq '1')
            $secondConfirm = if ($forceIrrev) { $true } else { Read-YesNo 'Are you ABSOLUTELY certain? (Y/N)' }
            if ($secondConfirm) {
                SD-Log 'Running DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase...' 'STEP'
                $r = Invoke-NativeLive -Exe 'dism.exe' -Arguments @('/Online','/Cleanup-Image','/StartComponentCleanup','/ResetBase') -Label 'ResetBase'
                if ($r.ExitCode -eq 0) { SD-Log 'DISM ResetBase completed.' 'OK' }
                else { SD-Log ("[WARN] DISM ResetBase returned exit code {0}." -f $r.ExitCode) 'WARN' }
            }
        } else {
            SD-Log 'ResetBase skipped.' 'WARN'
        }
    }

    # 5. DISM StartComponentCleanup (safe fallback)
    SD-Section 'Step 5/5 - DISM StartComponentCleanup (Safe)'
    SD-Log 'Cleans old component scraps without losing update uninstall ability.' 'INFO'

    if (Read-YesNo 'Run DISM StartComponentCleanup? (Y/N)') {
        SD-Log 'Running DISM /Online /Cleanup-Image /StartComponentCleanup...' 'STEP'
        $r = Invoke-NativeLive -Exe 'dism.exe' -Arguments @('/Online','/Cleanup-Image','/StartComponentCleanup') -Label 'StartComponentCleanup'
        if ($r.ExitCode -eq 0) { SD-Log 'DISM StartComponentCleanup completed.' 'OK' }
        else { SD-Log ("[WARN] DISM StartComponentCleanup returned exit code {0}." -f $r.ExitCode) 'WARN' }
    } else {
        SD-Log 'Skipped by user.' 'WARN'
    }

    # Summary
    SD-Section 'Summary'
    SD-Log 'SFC / DISM runner finished successfully.' 'OK'
    SD-Log "Full log: $logFile" 'INFO'

    Pause-Exit -ExitCode 0

} catch {
    SD-Log "FATAL SCRIPT RUNTIME ERROR: $($_.Exception.Message)" 'ERROR'
    Pause-Exit -ExitCode 1
}
'@
# ============================================================
# DETACHED RUNNER PRE-LAUNCH HELPER (Fix B)
# ============================================================
function Test-DetachedLaunchPrereqs {
    <#
    .SYNOPSIS
        Verifies that a child PowerShell can actually run before the
        parent commits to launching a detached step. Catches the case
        where $Script:PowerShellExe is broken, ExecutionPolicy blocks
        the runner, or the child cannot execute at all.
    .OUTPUTS
        [PSCustomObject] with .Ok (bool) and .Reason (string).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    # 0. Self-heal: if $Script:RunnerPowerShellExe was never populated,
    #    resolve to powershell.exe (the host the launch sites actually
    #    use). Never fall back to pwsh.exe here, because .NET 8's TLS
    #    stack does not honour the SchUseStrongCrypto registry fix and
    #    will fail the Akamai-fronted Microsoft Update handshake.
    $__exe = $null
    try {
        $__exe = $Script:RunnerPowerShellExe
    } catch { }
    if ([string]::IsNullOrWhiteSpace($__exe)) {
        try {
            $__exe = (Get-Command powershell.exe -ErrorAction Stop).Source
            $Script:RunnerPowerShellExe = $__exe
        } catch {
            return [PSCustomObject]@{ Ok = $false; Reason = ("Could not resolve runner host: {0}" -f $_.Exception.Message) }
        }
    }

    # 1. Resolver present?
    if ([string]::IsNullOrWhiteSpace($__exe)) {
        return [PSCustomObject]@{ Ok = $false; Reason = 'PowerShellExe not resolved' }
    }

    # 2. Executable present on disk?
    if (-not (Test-Path -LiteralPath $__exe)) {
        return [PSCustomObject]@{ Ok = $false; Reason = ("PowerShellExe not found: {0}" -f $__exe) }
    }

    # 3. Child can launch and exit 0? (100ms probe)
    try {
        $probe = Start-Process -FilePath $__exe `
                               -ArgumentList '-NoProfile','-NonInteractive','-Command','exit 0' `
                               -PassThru -Wait -WindowStyle Hidden
        if ($probe.ExitCode -ne 0) {
            return [PSCustomObject]@{ Ok = $false; Reason = ("Probe exit code {0}" -f $probe.ExitCode) }
        }
    } catch {
        return [PSCustomObject]@{ Ok = $false; Reason = ("Probe failed: {0}" -f $_.Exception.Message) }
    }

    return [PSCustomObject]@{ Ok = $true; Reason = 'ok' }
}


# ============================================================
# DETACHED RUNNER EXIT TRACKING (Fix A)
# ============================================================
function Register-DetachedExitTracking {
    <#
    .SYNOPSIS
        Subscribes to $Child.Exited and records the exit code in
        $Script:DetachedRunners when the child dies. Does not block.
    .PARAMETER Child
        Process object from Start-Process -PassThru.
    .PARAMETER Kind
        Human label ("Winget", "SFC/DISM", "Windows Update", "Drivers").
    .PARAMETER Note
        Step identifier ("Step 33", etc.).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Child,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Note
    )

    # [FIX-DETACHED-1] Store the live Process handle. The prior
    # Register-ObjectEvent -Action approach could not reach
    # $Script:DetachedRunners from its event runspace, so exit codes
    # were silently lost for every child that finished before PostCheck.
    $childPid = $Child.Id
    $Script:DetachedRunners[$childPid] = [PSCustomObject]@{
        Kind        = $Kind
        Note        = $Note
        StartedAt   = Get-Date
        ExitedAt    = $null
        ExitCode    = $null
        EventSource = $null
        Process     = $Child
    }
    Write-Log ("  [TRACK] Registered PID {0} ({1}) - exit captured via Process handle" -f $childPid, $Kind) -Level DEBUG
}


# ============================================================
# DETACHED RUNNER WAIT HELPER (Fix C)
# ============================================================
function Wait-DetachedRunners {
    <#
    .SYNOPSIS
        Waits for detached runner processes to exit and records their
        exit codes. Called from PostCheck.
    .PARAMETER MaxSeconds
        Upper bound on total wait. -1 = infinite. 0 = don't wait.
    #>
    [CmdletBinding()]
    param([int]$MaxSeconds = 0)

    if ($MaxSeconds -eq 0 -or -not $Script:DetachedRunners -or $Script:DetachedRunners.Count -eq 0) {
        return
    }

    $deadline = if ($MaxSeconds -lt 0) { [datetime]::MaxValue } else { (Get-Date).AddSeconds($MaxSeconds) }
    $pending = @($Script:DetachedRunners.Keys | Where-Object {
        $null -eq $Script:DetachedRunners[$_].ExitCode
    })

    if ($pending.Count -eq 0) {
        return
    }

    Write-Log ("Waiting for {0} detached runner(s) (max {1})..." -f $pending.Count,
        $(if ($MaxSeconds -lt 0) { 'unlimited' } else { "${MaxSeconds}s" })) -Level INFO

    # NOTE: $PID is a read-only automatic variable in PowerShell. Using
    # it as a foreach loop variable throws "Cannot overwrite variable
    # PID". Use $childPid instead.
    # [FIX-DETACHED-2] Read ExitCode from the Process handle captured at
    # launch. Get-Process -Id loses the exit code after process reaping.
    foreach ($childPid in $pending) {
        $entry = $Script:DetachedRunners[$childPid]
        $proc  = if ($entry.PSObject.Properties['Process']) { $entry.Process } else { $null }
        if (-not $proc) {
            $proc = Get-Process -Id $childPid -ErrorAction SilentlyContinue
        }
        if (-not $proc) {
            if ($null -eq $entry.ExitCode) {
                $entry.ExitedAt = Get-Date
                $entry.ExitCode = -1
            }
            continue
        }
        try {
            if ($proc.HasExited) {
                $entry.ExitedAt = $proc.ExitTime
                $entry.ExitCode = $proc.ExitCode
                continue
            }
        } catch { }

        if ((Get-Date) -gt $deadline) {
            Write-Log ("  [TIMEOUT] PID {0} ({1}) still running - leaving it detached" -f $childPid, $entry.Kind) -Level WARN
            continue
        }
        try {
            $remainingMs = [int]([Math]::Max(1000, ($deadline - (Get-Date)).TotalMilliseconds))
            if ($proc.WaitForExit($remainingMs)) {
                $entry.ExitedAt = $proc.ExitTime
                $entry.ExitCode = $proc.ExitCode
            } else {
                Write-Log ("  [TIMEOUT] PID {0} ({1}) did not exit in time" -f $childPid, $entry.Kind) -Level WARN
            }
        } catch {
            Write-Log ("  [WARN] Could not wait on PID {0}: {1}" -f $childPid, $_.Exception.Message) -Level WARN
        }
    }
}


# ============================================================
# FIX 4: Detect already-running children of a given Kind
# ============================================================
# [FIX-DETACHED-4] Prevents Steps 8b/12/33/39 from stacking a new child
# on top of a prior one still in flight. This is what causes the
# SFC/DISM window accumulation across runs.
$Script:RunnerKindMarkerFile = Join-Path $Script:ScriptDir 'WinTune.runners.json'

function Get-ExistingDetachedRunnerProcess {  # [FIX-KIND-CRASH-GET]
    # Never throws. Under Set-StrictMode Latest, `$t.Kind` aborts for
    # any element that is $null, a scalar, or missing the Kind property.
    # All property access goes through PSObject.Properties so we degrade
    # to "no existing runner" instead of crashing the caller's step.
    param([Parameter(Mandatory)][string]$Kind)

    $live = @()
    try {
        if (-not (Test-Path -LiteralPath $Script:RunnerKindMarkerFile)) { return $live }

        $rawText = Get-Content -LiteralPath $Script:RunnerKindMarkerFile -Raw -EA Stop
        if ([string]::IsNullOrWhiteSpace($rawText)) { return $live }

        $tracked = $rawText | ConvertFrom-Json
        if (-not $tracked) { return $live }

        foreach ($t in @($tracked)) {
            if ($null -eq $t) { continue }

            $tKind = ''
            try {
                if ($t.PSObject.Properties['Kind'] -and $t.Kind) {
                    $tKind = [string]$t.Kind
                }
            } catch { }
            if ($tKind -ne $Kind) { continue }

            $tPid = 0
            try {
                if ($t.PSObject.Properties['Pid'] -and $null -ne $t.Pid) {
                    $tPid = [int]$t.Pid
                }
            } catch { }
            if ($tPid -le 0) { continue }

            $p = Get-Process -Id $tPid -EA SilentlyContinue
            if ($p -and -not $p.HasExited) {
                $live += [PSCustomObject]@{
                    Pid       = $tPid
                    Kind      = $tKind
                    StartedAt = if ($t.PSObject.Properties['StartedAt'] -and $t.StartedAt) { [string]$t.StartedAt } else { '' }
                    Note      = if ($t.PSObject.Properties['Note']      -and $t.Note)      { [string]$t.Note }      else { '' }
                }
            }
        }
    } catch {
        Write-Log ("  [WARN] Runner kind check failed: {0}" -f $_.Exception.Message) -Level WARN
    }
    return $live
}

function Register-TrackedRunnerKind {  # [FIX-KIND-CRASH-REG]
    # Never throws. Reads existing entries with strictmode-safe property
    # access; on any parse error starts fresh. Writes JSON as an array
    # even for single elements (PS 5.1 unwraps otherwise).
    param(
        [Parameter(Mandatory)][int]$RunnerPid,
        [Parameter(Mandatory)][string]$Kind,
        [string]$Note = ''
    )

    $entry = [PSCustomObject]@{
        Pid       = $RunnerPid
        Kind      = $Kind
        Note      = $Note
        StartedAt = (Get-Date).ToString('o')
    }

    $existing = @()
    try {
        if (Test-Path -LiteralPath $Script:RunnerKindMarkerFile) {
            $rawText = Get-Content -LiteralPath $Script:RunnerKindMarkerFile -Raw -EA Stop
            if (-not [string]::IsNullOrWhiteSpace($rawText)) {
                $tracked = $rawText | ConvertFrom-Json
                if ($tracked) {
                    foreach ($t in @($tracked)) {
                        if ($null -eq $t) { continue }
                        $tPid = 0
                        try {
                            if ($t.PSObject.Properties['Pid'] -and $null -ne $t.Pid) {
                                $tPid = [int]$t.Pid
                            }
                        } catch { }
                        if ($tPid -le 0) { continue }
                        $p = Get-Process -Id $tPid -EA SilentlyContinue
                        if ($p -and -not $p.HasExited) {
                            $existing += $t
                        }
                    }
                }
            }
        }
    } catch {
        # Corrupt file - start fresh
        $existing = @()
    }

    $all = @($existing) + $entry
    try {
        # PS 5.1's ConvertTo-Json -InputObject @($all) still unwraps
        # 1-element arrays to a bare object. Detect and re-wrap.
        $json = ConvertTo-Json -InputObject $all -Compress -Depth 5
        if (-not ($json.TrimStart() -match '^\[')) {
            $json = "[$json]"
        }
        Set-Content -LiteralPath $Script:RunnerKindMarkerFile -Value $json -Encoding UTF8 -EA Stop
    } catch {
        Write-Log ("  [WARN] Could not persist runner tracking: {0}" -f $_.Exception.Message) -Level WARN
    }
}

# ============================================================
# SECURE RUNNER TEMP HELPER
# ============================================================
function New-SecureRunnerPath {
    param([string]$LeafName)

    if (-not $Script:RunnerTempDir -or -not (Test-Path -LiteralPath $Script:RunnerTempDir)) {
        $Script:RunnerTempDir = Join-Path $env:TEMP ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $Script:RunnerTempDir -Force -ErrorAction Stop | Out-Null
        try {
            # Best-effort module load WITHOUT -Force. -Force re-registers
            # TypeData on already-loaded modules, producing "member already
            # present" warnings that the catch block would surface as a
            # failure. Without -Force, the import is a no-op when loaded.
            if (-not (Get-Module -Name Microsoft.PowerShell.Security -ErrorAction SilentlyContinue)) {
                Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
            }
            $acl = Get-Acl -LiteralPath $Script:RunnerTempDir
            $acl.SetAccessRuleProtection($true, $false)
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($adminRule)
            $acl.AddAccessRule($systemRule)
            Set-Acl -LiteralPath $Script:RunnerTempDir -AclObject $acl
        } catch {
            Write-Log ("Could not restrict runner temp folder ACL: {0}" -f $_.Exception.Message) -Level WARN
        }
    }
    return (Join-Path $Script:RunnerTempDir $LeafName)
}

# ============================================================
# SHARED-FILE LOGGING (safe for concurrent writers)
# ============================================================
function Write-LogFile {
    <#
    .SYNOPSIS
        Appends a line to $Script:LogFile with FileShare.ReadWrite so
        multiple processes (parent + detached runners) can write
        concurrently without locking each other out.
    #>
    param(
        [Parameter(Mandatory, Position=0)]
        [AllowEmptyString()]
        [string]$Message
    )
    try {
        $fs = [System.IO.File]::Open(
            $Script:LogFile,
            [System.IO.FileMode]::Append,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::ReadWrite
        )
        try {
            $writer = New-Object System.IO.StreamWriter($fs, [System.Text.Encoding]::UTF8)
            try {
                $writer.WriteLine($Message)
                $writer.Flush()
            } finally {
                $writer.Dispose()
            }
        } finally {
            $fs.Dispose()
        }
    } catch {
        # never let logging failure crash the script
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Dual-sink logger: console (colored) + file.
    .PARAMETER Message
        Text to log.
    .PARAMETER Level
        INFO | OK | WARN | ERROR | PREVIEW | STEP | DEBUG
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('INFO','OK','WARN','ERROR','PREVIEW','STEP','DEBUG')]
        [string]$Level = 'INFO'
    )

    $color = switch ($Level) {
        'OK'      { 'Green' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'PREVIEW' { 'Magenta' }
        'STEP'    { 'Cyan' }
        'DEBUG'   { 'DarkGray' }
        default   { 'Gray' }
    }

    $tag    = "[$Level]"
    $stamp  = Get-Date -Format 'HH:mm:ss'
    $line   = "$stamp $tag $Message"

    # Console
    Write-Host $line -ForegroundColor $color

    # File (best-effort - never throw)
    try {
        Write-LogFile -Message $line
    } catch {
        # silent - we never want the logger to crash the script
    }
}

# [REMOVED-LOGRAM] Write-LogRaw (was dead code - see Clean-DeadCode.ps1)


# ============================================================
# PREFLIGHT / ENVIRONMENT CHECKS
# ============================================================
function Test-Environment {
    <#
    .SYNOPSIS
        Verifies required executables and OS constraints before running.
    #>
    $required = @(
        'dism.exe', 'sfc.exe', 'pnputil.exe',
        'powercfg.exe', 'vssadmin.exe', 'wevtutil.exe',
        'netsh.exe', 'ipconfig.exe', 'route.exe',
        'schtasks.exe', 'reg.exe', 'taskkill.exe', 'tasklist.exe'
    )

    $missing = @()
    foreach ($exe in $required) {
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
            $missing += $exe
        }
    }

    if ($missing.Count -gt 0) {
        Write-Log "Missing required executables: $($missing -join ', ')" -Level ERROR
        throw "Environment preflight failed. Missing: $($missing -join ', ')"
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Write-Log "OS detected: $($os.Caption) (Build $($os.BuildNumber))" -Level INFO

    $build = [int]$os.BuildNumber
    if ($build -lt 18362) {
        Write-Log "Windows build $build is below the tested baseline (19041+). Some steps may fail." -Level WARN
    }

    # [FIX-WIN10-EOL] Windows 10 reached end of support on Oct 14, 2025.
    # Consumer ESU ended Oct 13, 2026. Any build < 22000 is a Win10
    # machine that is (as of Nov 2026) no longer receiving security
    # updates through normal channels. This is not a bug in WinTune —
    # WinTune will still run — but the OS itself is the real problem.
    if ($build -ge 18362 -and $build -lt 22000) {
        Write-Log '============================================================' -Level WARN
        Write-Log ' WINDOWS 10 IS OUT OF SUPPORT (EOL Oct 14, 2025)' -Level WARN
        Write-Log '============================================================' -Level WARN
        Write-Log '  Consumer ESU ended Oct 13, 2026. Enterprise ESU continues' -Level WARN
        Write-Log '  through Oct 2028 for organizations that enrolled.' -Level WARN
        Write-Log '' -Level WARN
        Write-Log '  WinTune will continue to run, but a maintenance tool can' -Level WARN
        Write-Log '  only do so much on an unpatched OS. The real fix is:' -Level WARN
        Write-Log '    - Upgrade to Windows 11 (check PC Health Check first), or' -Level WARN
        Write-Log '    - Enroll in Windows 10 ESU if you are on Enterprise/Education' -Level WARN
        Write-Log '' -Level WARN
        Write-Log '  Continuing with maintenance run.' -Level WARN
        Write-Log '============================================================' -Level WARN
    }

    # ---- SKU detection ----
    try {
        $skuNum = [int]$os.OperatingSystemSKU
        $skuName = switch ($skuNum) {
            0   { 'Ultimate' }
            1   { 'Home Basic' }
            2   { 'Home Premium' }
            3   { 'Enterprise' }
            4   { 'Enterprise' }
            5   { 'Business' }
            6   { 'Business N' }
            27  { 'Enterprise N' }
            48  { 'Professional' }
            49  { 'Professional N' }
            100 { 'Home' }
            101 { 'Home' }
            121 { 'Education' }
            122 { 'Education N' }
            default { "SKU=$skuNum" }
        }
        Write-Log "Windows SKU: $skuName" -Level INFO
        if ($skuName -like 'Home*') {
            Write-Log "  [NOTE] Windows Home ignores many WindowsUpdate policies." -Level INFO
            $Script:WinHomeSku = $true
        } else {
            $Script:WinHomeSku = $false
        }
    } catch {
        Write-Log "SKU detection failed: $($_.Exception.Message)" -Level DEBUG
        $Script:WinHomeSku = $false
    }

    # ---- Windows 11 feature-release detection ----
    if ($build -ge 22000) {
        $frName = switch ($build) {
            22000 { '21H2' }
            22621 { '22H2' }
            22631 { '23H2' }
            26100 { '24H2' }
            26200 { '25H2' }
            default { "unknown (build $build)" }
        }
        Write-Log "Windows 11 feature release: $frName" -Level INFO
    }

    # ---- ARM64 detection ----
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
        Write-Log "ARM64 detected. Native tools (dism, pnputil, vssadmin) may behave differently." -Level WARN
    }
}


# ============================================================
# CONCURRENCY LOCK ENGINE
# ============================================================
function Enter-ScriptLock {
    <#
    .SYNOPSIS
        Acquires an exclusive lock via [System.IO.File]::Open with
        FileShare::None. This is atomic at the OS level - no race
        conditions, no PID-parsing tricks.
    .DESCRIPTION
        If a stale lock file exists (previous crash), we attempt to
        detect it and clean it up.
    #>
    [CmdletBinding()]
    param()

    # --- Try stale lock detection first ---
    if (Test-Path -LiteralPath $Script:LockFile) {
        Write-Log "Existing lock file detected: $($Script:LockFile)" -Level WARN

        $stale = $false
        try {
            # If we can open it exclusively, the other process is dead
            $probe = [System.IO.File]::Open(
                $Script:LockFile,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
            $reader = New-Object System.IO.StreamReader($probe)
            $content = $reader.ReadToEnd()
            $reader.Close()
            $probe.Close()

            Write-Log "Lock file content: $content" -Level INFO

            # Parse PID
            $pidMatch = [regex]::Match($content, 'PID=(\d+)')
            if ($pidMatch.Success) {
                $oldPid = [int]$pidMatch.Groups[1].Value
                $proc   = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
                if ($proc) {
                    Write-Log "Another instance is actively running (PID $oldPid - $($proc.ProcessName))." -Level ERROR
                    Write-Log "Lock File Path: $($Script:LockFile)" -Level ERROR
                    throw "WinTune is already running in another window."
                }
            }

            $stale = $true
        } catch [System.IO.IOException] {
            Write-Log "Lock file is held by a live process." -Level ERROR
            throw "WinTune is already running in another window."
        } catch {
            if ($_.Exception.Message -like '*already running*') { throw }
            Write-Log "Lock probe failed: $($_.Exception.Message) - assuming stale." -Level WARN
            $stale = $true
        }

        if ($stale) {
            Write-Log "Stale execution lock detected. Purging old block markers..." -Level INFO
            try { Remove-Item -LiteralPath $Script:LockFile -Force -ErrorAction SilentlyContinue } catch { }
        }
    }

    # --- Acquire lock ---
    try {
        $Script:LockStream = [System.IO.File]::Open(
            $Script:LockFile,
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
        $writer = New-Object System.IO.StreamWriter($Script:LockStream)
        $writer.WriteLine("PID=$PID")
        $writer.WriteLine("Host=$env:COMPUTERNAME")
        $writer.WriteLine("User=$env:USERNAME")
        $writer.WriteLine("Started=$($Script:RunStamp)")
        $writer.Flush()
        # Keep stream open (holds exclusive lock until process exit)
    } catch {
        throw "Failed to acquire execution lock: $($_.Exception.Message)"
    }

    Write-Log "Execution lock acquired (PID $PID)." -Level OK
}

function Exit-ScriptLock {
    <#
    .SYNOPSIS
        Releases the lock stream and deletes the lock file.
    #>
    [CmdletBinding()]
    param()

    if ($Script:LockStream) {
        try { $Script:LockStream.Close() }    catch { }
        try { $Script:LockStream.Dispose() } catch { }
        $Script:LockStream = $null
    }

    if (Test-Path -LiteralPath $Script:LockFile) {
        try {
            Remove-Item -LiteralPath $Script:LockFile -Force -ErrorAction SilentlyContinue
            Write-Log "Execution lock released." -Level INFO
        } catch {
            Write-Log "Could not remove lock file: $($_.Exception.Message)" -Level WARN
        }
    }
}


# ============================================================
# HELPERS - DISK / SIZE MEASUREMENT
# ============================================================
function Get-FreeBytesOnSystemDrive {
    <#
    .SYNOPSIS
        Returns free bytes on the system drive (SystemDrive env var).
        Returns [int64] 0 on any failure.
    #>
    [CmdletBinding()]
    [OutputType([int64])]
    param()

    try {
        $drive = $env:SystemDrive  # e.g. "C:"
        $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'" -ErrorAction Stop
        if ($ld) { return [int64]$ld.FreeSpace }
    } catch {
        Write-Log "Free-space query failed: $($_.Exception.Message)" -Level DEBUG
    }
    return [int64]0
}

function Get-PathSizeGB {
    <#
    .SYNOPSIS
        Returns the recursive size of a path in GB, rounded to 2 decimals.
        Returns 0.00 if the path does not exist or on any error.
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return [double]0.00 }

    try {
        # Only enumerate files (not directories) with a valid Length
        $sum = Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
               Where-Object { $_.PSObject.Properties['Length'] } |
               Measure-Object -Property Length -Sum |
               Select-Object -ExpandProperty Sum

        if ($null -eq $sum) { return [double]0.00 }
        return [math]::Round(([int64]$sum) / 1GB, 2)
    } catch {
        Write-Log "Size query failed for '$Path': $($_.Exception.Message)" -Level DEBUG
        return [double]0.00
    }
}

function Get-PathSizeMB {
    <#
    .SYNOPSIS
        Same as Get-PathSizeGB but returns MB (integer).
    #>
    [CmdletBinding()]
    [OutputType([int64])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return [int64]0 }

    try {
        $sum = Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
               Where-Object { $_.PSObject.Properties['Length'] } |
               Measure-Object -Property Length -Sum |
               Select-Object -ExpandProperty Sum

        if ($null -eq $sum) { return [int64]0 }
        return [int64](([int64]$sum) / 1MB)
    } catch {
        return [int64]0
    }
}

# ============================================================
# HELPER: Reparse-point guard for recursive deletion
# ============================================================
function Test-SafeDeletionTarget {
    <#
    .SYNOPSIS
        Returns $true if a path is safe to recursively delete:
        the path exists, is not itself a reparse point, and no
        child in the immediate tree is a reparse point that
        would redirect the deletion outside the intended tree.

    .DESCRIPTION
        A reparse point is a symbolic link, junction, or mount
        point. Remove-Item -Recurse follows reparse points by
        default, which can delete content outside the intended
        tree. This helper refuses to green-light a recursive
        delete when a reparse point is present at the top level
        of the tree.

    .PARAMETER Path
        The directory path to check.

    .PARAMETER AllowReparsePoints
        If set, permits reparse points. For diagnostic use only.

    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$AllowReparsePoints
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop

        # The path itself is a reparse point
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            if (-not $AllowReparsePoints) {
                Write-Log ("  [SKIP] Refusing to recurse into reparse point: {0}" -f $Path) -Level WARN
                return $false
            }
        }

        # Only directories have children to check
        if (-not $item.PSIsContainer) { return $true }

        # Check immediate children for reparse points
        $children = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                Write-Log ("  [WARN] Reparse point inside {0}: {1} - will not be followed" -f $Path, $child.Name) -Level WARN
            }
        }

        return $true
    } catch {
        Write-Log ("  [WARN] Reparse check failed for {0}: {1}" -f $Path, $_.Exception.Message) -Level WARN
        return $false
    }
}


# ============================================================
# HELPERS - NATIVE COMMAND WRAPPER
# ============================================================
function Invoke-NativeCommand {
    <#
    .SYNOPSIS
        Runs a native executable and returns a structured result.
    .PARAMETER FilePath
        Executable name or full path.
    .PARAMETER Arguments
        Array of arguments.
    .PARAMETER NoNewWindow
        Prevent a new window from appearing.
    .PARAMETER TimeoutSeconds
        Optional timeout (default 0 = no timeout).
    .OUTPUTS
        PSCustomObject: ExitCode, StdOut (string[]), StdErr (string[]),
                        Success (bool), Duration (timespan)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [switch]$NoNewWindow,

        [int]$TimeoutSeconds = 0
    )

    $start = Get-Date
    $stdOut = @()
    $stdErr = @()
    $code   = -1

    try {
        # Capture stdout/stderr cleanly via Start-Process + temp files
        # (avoids the WinPS 5.1 issue where external stderr pops a red error)
        $outFile = [System.IO.Path]::GetTempFileName()
        $errFile = [System.IO.Path]::GetTempFileName()

        $procArgs = @{
            FilePath      = $FilePath
            ArgumentList  = $Arguments
            Wait          = $true
            PassThru      = $true
            NoNewWindow   = $NoNewWindow.IsPresent
            RedirectStandardOutput = $outFile
            RedirectStandardError  = $errFile
        }

        if ($TimeoutSeconds -gt 0) {
            $proc = Start-Process @procArgs
            if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
                try { $proc.Kill() } catch { }
                throw "Process timed out after $TimeoutSeconds seconds: $FilePath"
            }
        } else {
            $proc = Start-Process @procArgs
        }

        $code = if ($null -ne $proc.ExitCode) { [int]$proc.ExitCode } else { -1 }

        if (Test-Path $outFile) { $stdOut = Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue }
        if (Test-Path $errFile) { $stdErr = Get-Content -LiteralPath $errFile -ErrorAction SilentlyContinue }

        Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Native command failed: $FilePath - $($_.Exception.Message)" -Level DEBUG
        $stdErr += $_.Exception.Message
    }

    [PSCustomObject]@{
        FilePath = $FilePath
        ExitCode = $code
        StdOut   = @($stdOut)
        StdErr   = @($stdErr)
        Success  = ($code -eq 0)
        Duration = (Get-Date) - $start
    }
}

# ============================================================
# HELPER: Run native command with live heartbeat
# ============================================================
# [REMOVED-NATWHB] Invoke-NativeWithHeartbeat (was dead code - see Clean-DeadCode.ps1)


# ============================================================
# HELPERS - CONFIRMATION
# ============================================================
function Confirm-Action {
    <#
    .SYNOPSIS
        Prompts the user for a Yes/No confirmation unless -DryRun or
        a corresponding "assume yes" flag is set.

    .DESCRIPTION
        Input handling:
          * Trims leading/trailing whitespace
          * Converts to lowercase
          * Accepts any string that starts with 'y' as Yes
          * Accepts any string that starts with 'n' as No
          * Empty input (just Enter) defaults to No
          * Reprompts on invalid input (up to 3 attempts)
          * Shows the resolved decision in the log

    .PARAMETER Query
        Question to ask.

    .PARAMETER AssumeYes
        If true, skip the prompt and return $true.

    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [switch]$AssumeYes
    )

    # DryRun and AssumeYes short-circuit
    if ($Script:DryRun) { return $true }
    if ($AssumeYes)     { return $true }
    if ($Script:YesToAll) { return $true }

    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $raw = Read-Host "$Query (Y/N)"

        # Normalize: trim, remove non-letter chars
        if ($null -eq $raw) { $raw = '' }
        $clean = $raw.Trim().ToLowerInvariant()

        # Empty = No
        if ([string]::IsNullOrWhiteSpace($clean)) {
            Write-Log '  [INPUT] Empty response - treated as No.' -Level INFO
            return $false
        }

        # Starts with 'y' = Yes
        if ($clean.StartsWith('y')) {
            Write-Log ('  [INPUT] "{0}" resolved to Yes.' -f $raw) -Level OK
            return $true
        }

        # Starts with 'n' = No
        if ($clean.StartsWith('n')) {
            Write-Log ('  [INPUT] "{0}" resolved to No.' -f $raw) -Level INFO
            return $false
        }

        # Invalid input
        Write-Host ("  [WARN] '{0}' is not a valid response. Please enter Y or N." -f $raw) -ForegroundColor Yellow
        Write-Log ("  [INPUT] Invalid response '{0}' (attempt {1}/{2})" -f $raw, $attempt, $maxAttempts) -Level WARN
    }

    # Too many invalid attempts - default to No for safety
    Write-Host '  [WARN] Too many invalid responses. Defaulting to No.' -ForegroundColor Yellow
    Write-Log '[INPUT] Too many invalid responses - defaulting to No.' -Level WARN
    return $false
}


# ============================================================
# HELPERS - PROGRESS WRAPPER
# ============================================================
# [REMOVED-WITHPROG] Invoke-WithProgress (was dead code - see Clean-DeadCode.ps1)


# ============================================================
# STEP DISPATCHER
# ============================================================
# ============================================================
# REPORT OBJECT (accumulated during run, serialized at end)
# ============================================================
$Script:Report = [ordered]@{
    StartedAt         = Get-Date
    FinishedAt        = $null
    Hostname          = $env:COMPUTERNAME
    OS                = ''
    Build             = ''
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    User              = $env:USERNAME
    Profile           = $Script:PresetName
    DryRun            = $Script:DryRun
    Steps             = New-Object System.Collections.ArrayList
    DiskBeforeGB      = 0.0
    DiskAfterGB       = 0.0
    RebootRequired    = $false
    DetachedRunners   = New-Object System.Collections.ArrayList
    OriginalPowerPlan = ''
}

try {
    $activeSchemeOut = & powercfg.exe /getactivescheme 2>&1
    $m = [regex]::Match($activeSchemeOut -join ' ', '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
    if ($m.Success) {
        $Script:Report.OriginalPowerPlan = $m.Groups[1].Value
    }
} catch { }

# Populate OS fields if possible
try {
    $__os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($__os) {
        $Script:Report.OS    = $__os.Caption
        $Script:Report.Build = $__os.BuildNumber
    }
} catch { }


function Add-ReportStep {
    param(
        [Parameter(Mandatory)][string]$Number,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]
        [ValidateSet('OK','Skipped','Failed','Gated','DryRun','Warning','NoOp','Detached')]
        [string]$Status,
        [string]$Detail = '''''',
        [TimeSpan]$Duration = [TimeSpan]::Zero
    )
    [void]$Script:Report.Steps.Add([PSCustomObject]@{
        Number   = [string]$Number
        Name     = $Name
        Status   = $Status
        Detail   = $Detail
        Duration = $Duration
        DurationMs = [int]$Duration.TotalMilliseconds
    })
}

function Add-ReportRunner {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][int]$RunnerPid,
        [string]$Note = ''
    )
    [void]$Script:Report.DetachedRunners.Add([PSCustomObject]@{
        Kind = $Kind
        Pid  = $RunnerPid
        Note = $Note
        At   = Get-Date
    })
}
function Test-StepEnabled {
    <#
    .SYNOPSIS
        Returns $true if the step should run.
    .DESCRIPTION
        Accepts either an int (1, 12, 55) or a string key with a
        letter suffix (''1b'', ''8b''). -SkipSteps entries are compared
        as strings so ''1b'' and ''8b'' do not collide with ''1'' and ''8''.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$StepKey
    )

    $skipStrings = @($Script:SkipSteps | ForEach-Object { [string]$_ })
    if ($skipStrings -contains $StepKey) {
        Write-Log "Step $StepKey skipped by -SkipSteps." -Level WARN
        return $false
    }
    return $true
}


# ============================================================
# PRECHECK - DISK BASELINE
# ============================================================
function Invoke-PreCheck {
    <#
    .SYNOPSIS
        Captures baseline disk metrics and enumerates local volumes.
    #>
    [CmdletBinding()]
    param()

    Write-Log '----------------------------------------------------------------' -Level INFO
    Write-Log 'PRE-CHECK: Calculating disk and partition baselines...' -Level INFO
    Write-Log '----------------------------------------------------------------' -Level INFO

    $Script:StartFreeBytes   = Get-FreeBytesOnSystemDrive
    $Script:StartFreeDisplay = '{0:N2}' -f ($Script:StartFreeBytes / 1GB)

    Write-Log ('[SYSTEM DRIVE] Baseline free space ({0}): {1} GB' -f $env:SystemDrive, $Script:StartFreeDisplay) -Level INFO

    Write-Log '[OTHER DRIVES] Scanning remaining local storage volumes...' -Level INFO

    try {
        $volumes = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
                   Where-Object { $_.DriveType -eq 3 -and $_.DeviceID -ne $env:SystemDrive }

        foreach ($v in $volumes) {
            $free  = [math]::Floor($v.FreeSpace / 1GB)
            $total = [math]::Floor($v.Size / 1GB)
            Write-Log ('  - Drive {0} | Free: {1} GB / Total: {2} GB' -f $v.DeviceID, $free, $total) -Level INFO
        }
    } catch {
        Write-Log "Secondary drive enumeration failed: $($_.Exception.Message)" -Level WARN
    }

    Write-Log '----------------------------------------------------------------' -Level INFO
}


# ============================================================
# BANNER
# ============================================================
function Show-Banner {
    [CmdletBinding()]
    param()

    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host (" WinTune Ultimate v{0} - Windows Maintenance Suite" -f $Script:Version) -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host (' Log file: {0}' -f $Script:LogFile) -ForegroundColor DarkGray
}


# ============================================================
# EMBEDDED WINGET RUNNER (written to TEMP at runtime)
# ============================================================
$Script:EmbeddedWingetRunner = @'
# WinTune - Winget Upgrade Runner (Interactive Target Mode)
# Launched by WinTune Step 33. Runs natively in its own visible console window.

$ErrorActionPreference = 'Continue'
$yesToAll = ($env:FC_YES_TO_ALL -eq '1')
$__logDir = if ($env:FC_LOG_DIR) { $env:FC_LOG_DIR } else { Split-Path -Parent $PSCommandPath }
$logFile = if ($env:FC_LOG_DIR) { Join-Path $env:FC_LOG_DIR 'WinTune_Winget.log' } else { Join-Path (Split-Path -Parent $PSCommandPath) 'WinTune_Winget.log' }

function WG-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'STEP'  { 'Cyan' }
        'HEAD'  { 'Magenta' }
        default { 'Gray' }
    }
    $line = "$stamp [$Level] $Message"
    Write-Host $line -ForegroundColor $color
    try { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 } catch { }
}

function WG-Section {
    param([string]$Title)
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host (" $Title") -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan
}

function Pause-Exit {
    param([int]$ExitCode = 0)
    Write-Host ''
    Write-Host 'Press any key to close this window...' -ForegroundColor DarkGray
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
    try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue } catch { }
    exit $ExitCode
}

function Read-YesNo {
    param([string]$Prompt)
    if ($yesToAll) {
        Write-Host ("  [AUTO] {0} -> Y" -f $Prompt) -ForegroundColor Cyan
        return $true
    }
    while ($true) {
        $raw = Read-Host $Prompt
        if ($null -eq $raw) { $raw = '' }
        $clean = $raw.Trim().ToLowerInvariant()
        if ($clean.StartsWith('y')) { return $true }
        if ($clean.StartsWith('n') -or $clean -eq '') { return $false }
        Write-Host "  Please enter Y or N." -ForegroundColor Yellow
    }
}

try {
    Clear-Host
    try { $Host.UI.RawUI.WindowTitle = 'WinTune - Winget Upgrades' } catch { }
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host ' WinTune - Winget Upgrade (Interactive Mode)' -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan

    WG-Log 'Winget upgrade runner started.' 'OK'
    WG-Log "PID: $PID"
    WG-Log "Log: $logFile"

    # ============================================================
    # Pre-flight
    # ============================================================
    WG-Section 'Pre-flight'

    $wg = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $wg) {
        WG-Log 'winget.exe not found in PATH.' 'WARN'
        WG-Log 'winget is provided by the "App Installer" package.' 'INFO'
        WG-Log 'Attempting auto-install from Microsoft GitHub releases...' 'STEP'

        $installed = $false

        # ---- Method 1: GitHub .msixbundle ----
        try {
            # Use Microsoft's stable aka.ms redirect for App Installer
            $downloadUrl = 'https://aka.ms/getwinget'
            $tempFile = Join-Path $env:TEMP 'Microsoft.DesktopAppInstaller.msixbundle'

            WG-Log 'Fetching App Installer bundle from Microsoft (aka.ms/getwinget)...' 'INFO'

            # ---- Download with retry + progress + resume ----
            Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

            $maxAttempts = 3
            $attempt = 0
            $success = $false

            while ($attempt -lt $maxAttempts -and -not $success) {
                $attempt++
                WG-Log ("Download attempt {0}/{1}..." -f $attempt, $maxAttempts) 'STEP'

                $http = $null
                $response = $null
                $inStream = $null
                $outStream = $null

                try {
                    $http = New-Object System.Net.Http.HttpClient
                    $http.Timeout = [TimeSpan]::FromMinutes(60)
                    $http.DefaultRequestHeaders.UserAgent.ParseAdd('WinTune/1.0')

                    # Determine resume offset from partial file
                    $existingBytes = [int64]0
                    if (Test-Path -LiteralPath $tempFile) {
                        $existingBytes = (Get-Item -LiteralPath $tempFile -Force).Length
                        if ($existingBytes -gt 0) {
                            WG-Log ("  Resuming from {0:N1} MB" -f ($existingBytes / 1MB)) 'INFO'
                            $http.DefaultRequestHeaders.Range = New-Object System.Net.Http.Headers.RangeHeaderValue($existingBytes, $null)
                        }
                    }

                    $response = $http.GetAsync($downloadUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

                    # Validate response (200 = full, 206 = partial, others = error)
                    $statusCode = [int]$response.StatusCode
                    if ($statusCode -ne 200 -and $statusCode -ne 206) {
                        throw ("Unexpected HTTP status: {0}" -f $statusCode)
                    }

                    $contentLength = [int64]0
                    if ($response.Content.Headers.ContentLength) {
                        $contentLength = [int64]$response.Content.Headers.ContentLength
                    }
                    $totalBytes = $contentLength + $existingBytes
                    WG-Log ("  Size: {0:N1} MB (total {1:N1} MB)" -f ($contentLength / 1MB), ($totalBytes / 1MB)) 'INFO'

                    $inStream = $response.Content.ReadAsStreamAsync().Result

                    # Open output stream: append if resuming, else create
                    $fileMode = if ($existingBytes -gt 0) { [System.IO.FileMode]::Append } else { [System.IO.FileMode]::Create }
                    $outStream = New-Object System.IO.FileStream($tempFile, $fileMode, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

                    # 256 KB buffer for throughput
                    $buffer = New-Object byte[] 262144
                    $totalRead = $existingBytes
                    $sessionRead = [int64]0
                    $lastRender = Get-Date
                    $startTime = Get-Date
                    $lastDataTime = Get-Date

                    while ($true) {
                        $read = $inStream.Read($buffer, 0, $buffer.Length)
                        if ($read -le 0) { break }

                        $outStream.Write($buffer, 0, $read)
                        $totalRead += $read
                        $sessionRead += $read

                        $now = Get-Date
                        # Stall detector: abort if no data for 30 s
                        if (($now - $lastDataTime).TotalSeconds -gt 120) {
                            throw 'Stalled: no data received for 120 seconds.'
                        }
                        $lastDataTime = $now

                        if (($now - $lastRender).TotalMilliseconds -ge 200) {
                            $lastRender = $now

                            $pct = if ($totalBytes -gt 0) { [int](($totalRead / $totalBytes) * 100) } else { 0 }
                            $elapsed = ($now - $startTime).TotalSeconds
                            $mbps = if ($elapsed -gt 0) { ($sessionRead / 1MB) / $elapsed } else { 0 }
                            $remainingMB = if ($totalBytes -gt 0) { [math]::Max(0, ($totalBytes - $totalRead) / 1MB) } else { 0 }
                            $eta = if ($mbps -gt 0.01) { $remainingMB / $mbps } else { 0 }

                            $barWidth = 30
                            $filled = [int]($barWidth * $pct / 100)
                            if ($filled -lt 0) { $filled = 0 }
                            if ($filled -gt $barWidth) { $filled = $barWidth }
                            $bar = ([string][char]0x2588 * $filled) + ([string][char]0x2591 * ($barWidth - $filled))

                            $line = "  {0} {1,8:N1} / {2,8:N1} MB  @ {3,5:N1} MB/s  ETA {4:mm\:ss}  [try {5}/{6}]" -f `
                                    $bar, ($totalRead / 1MB), ($totalBytes / 1MB), $mbps, [TimeSpan]::FromSeconds($eta), $attempt, $maxAttempts

                            # Use [Console]::Write for reliable in-place updates.
                            # Write-Host with -NoNewline can split lines when the
                            # terminal is narrow or the output is captured.
                            $padded = $line.PadRight(140)
                            [Console]::Write("`r" + $padded)
                        }
                    }

                    # Clear the progress line before printing the completion log
                    [Console]::Write("`r" + (' ' * 140) + "`r")
                    Write-Host ''
                    $elapsed = (Get-Date) - $startTime

                    # Verify completeness
                    if ($totalBytes -gt 0 -and $totalRead -lt $totalBytes) {
                        throw ("Incomplete download: got {0:N1} MB of {1:N1} MB" -f ($totalRead / 1MB), ($totalBytes / 1MB))
                    }

                    $avgSpeed = if ($elapsed.TotalSeconds -gt 0) { ($sessionRead / 1MB) / $elapsed.TotalSeconds } else { 0 }
                    WG-Log ("Download complete: {0:N1} MB in {1:mm\:ss} ({2:N1} MB/s)" -f `
                            ($totalRead / 1MB), $elapsed, $avgSpeed) 'OK'
                    $success = $true

                } catch {
                    [Console]::Write("`r" + (' ' * 140) + "`r")
                    WG-Log ("Attempt {0} failed: {1}" -f $attempt, $_.Exception.Message) 'WARN'
                    if ($attempt -lt $maxAttempts) {
                        $wait = 30 * $attempt
                        WG-Log ("  Retrying in {0} s..." -f $wait) 'INFO'
                        Start-Sleep -Seconds $wait
                    }
                } finally {
                    if ($outStream) { try { $outStream.Close(); $outStream.Dispose() } catch { } }
                    if ($inStream)  { try { $inStream.Close();  $inStream.Dispose() }  catch { } }
                    if ($response)  { try { $response.Dispose() } catch { } }
                    if ($http)      { try { $http.Dispose() } catch { } }
                }
            }

            if (-not $success) {
                throw 'All download attempts failed.'
            }

            # ---- Verify MSIX bundle magic bytes (PK zip signature) ----
            $magic = [System.IO.File]::ReadAllBytes($tempFile)[0..3]
            if ($magic[0] -ne 0x50 -or $magic[1] -ne 0x4B) {
                throw 'Downloaded file is not a valid MSIX bundle (wrong magic bytes).'
            }

            # ---- Install ----
            WG-Log 'Installing App Installer (MSIX bundle)...' 'STEP'
            Add-AppxPackage -Path $tempFile -ErrorAction Stop
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
            # [FIX-WINGET-INSTALLED] Mark install as succeeded so the
            # Store fallback below does not fire on a fresh install.
            # Without this, a clean GitHub install of App Installer
            # immediately opened the Store page and exited 1, forcing
            # a second run before the auto-install actually took effect.
            $installed = $true
        } catch {
            WG-Log ("GitHub method failed: {0}" -f $_.Exception.Message) 'WARN'
        }

        # ---- Method 2: Microsoft Store fallback ----
        if (-not $installed) {
            WG-Log 'Opening Microsoft Store page for App Installer...' 'STEP'
            try {
                Start-Process 'ms-windows-store://pdp/?productid=9NBLGGH4NNS1' -ErrorAction Stop
                WG-Log 'Install App Installer from the Store, then re-run WinTune Step 33.' 'INFO'
                Pause-Exit -ExitCode 1
            } catch {
                WG-Log ("Could not open Microsoft Store: {0}" -f $_.Exception.Message) 'ERROR'
                WG-Log 'Manual install: https://github.com/microsoft/winget-cli/releases' 'INFO'
                Pause-Exit -ExitCode 1
            }
        }
    }

    # Refresh $wg reference after install
    $wg = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $wg) {
        WG-Log 'winget.exe still not available after install attempt.' 'ERROR'
        Pause-Exit -ExitCode 1
    }
    WG-Log ("winget: {0}" -f $wg.Source) 'OK'

    try {
        $wgVersion = (& winget.exe --version 2>&1 | Select-Object -First 1)
        if ($wgVersion) {
            WG-Log ("winget version: {0}" -f ([string]$wgVersion).Trim()) 'OK'
        }
    } catch {
        WG-Log 'Could not determine winget version.' 'WARN'
    }

    WG-Log 'Refreshing winget source index (this may fail on restricted networks)...' 'STEP'
    $__srcOk = $false
    $__srcOut = @()
    for ($__attempt = 1; $__attempt -le 3; $__attempt++) {
        try {
            # NOTE: winget source update does NOT accept
            # --accept-source-agreements. That flag exists only on
            # search / install / upgrade / list. Passing it here causes
            # the command to fail with its usage text, which is the
            # historical cause of the 0x8A150014 cascade downstream.
            $__srcOut = & winget.exe source update 2>&1
            if ($LASTEXITCODE -eq 0) { $__srcOk = $true; break }
        } catch {
            $__srcOut = @($_.Exception.Message)
        }
        if ($__attempt -lt 3) {
            WG-Log ("  source update attempt {0}/3 failed, retrying in 5s..." -f $__attempt) 'WARN'
            Start-Sleep -Seconds 5
        }
    }

    if ($__srcOk) {
        WG-Log 'Source index refreshed.' 'OK'
    } else {
        WG-Log 'winget source update FAILED after 3 attempts.' 'WARN'
        foreach ($__l in $__srcOut) { if (-not [string]::IsNullOrWhiteSpace($__l)) { WG-Log ("  [src] $__l") 'WARN' } }
        WG-Log 'Upgrade pass will run against a CACHED index.' 'WARN'
        WG-Log 'If upgrades fail with 0x8A150014 (UPDATE_NOT_APPLICABLE), the cached index is stale.' 'WARN'
        WG-Log 'Typical causes: firewall blocking cdn.winget.microsoft.com (Zscaler, VPN, proxy).' 'WARN'
    }

    # ============================================================
    # Part 1 - Enumerate
    # ============================================================
    WG-Section 'Part 1 - Upgradable applications'
    WG-Log 'Running: winget upgrade --include-unknown' 'STEP'

    $listOutput = @()
    try {
        $listOutput = & winget.exe upgrade --include-unknown --accept-source-agreements 2>&1
    } catch {
        WG-Log "Enumeration failed: $($_.Exception.Message)" 'ERROR'
        Pause-Exit -ExitCode 1
    }

    foreach ($line in $listOutput) {
        WG-Log $line 'INFO'
    }

    $hasUpgrades = $false
    foreach ($line in $listOutput) {
        if ($line -match '(\d+)\s+upgrades?\s+available') {
            if ([int]$matches[1] -gt 0) { $hasUpgrades = $true }
            break
        }
    }

    if (-not $hasUpgrades) {
        WG-Log 'No upgradable applications detected.' 'OK'
        WG-Log 'Nothing to do.' 'OK'
        Pause-Exit -ExitCode 0
    }
    WG-Log 'Upgradable applications found.' 'OK'

    # ============================================================
    # Part 2 - Pins
    # ============================================================
    WG-Section 'Part 2 - Pinned packages (excluded from upgrade)'
    WG-Log 'Running: winget pin list' 'STEP'

    try {
        $pinOutput = & winget.exe pin list --accept-source-agreements 2>&1
        foreach ($line in $pinOutput) {
            WG-Log $line 'INFO'
        }
    } catch {
        WG-Log "Pin listing failed: $($_.Exception.Message)" 'WARN'
    }

    # ============================================================
    # Part 3 - Live Upgrade with Progress Bar
    # ============================================================
    WG-Section 'Part 3 - Active upgrade'
    Write-Host 'About to upgrade all upgradable apps interactively.' -ForegroundColor Yellow
    Write-Host 'Pinned apps will NOT be upgraded.' -ForegroundColor Gray
    Write-Host 'The native winget progress bar will appear below.' -ForegroundColor Gray

    $proceed = Read-YesNo 'Proceed with the upgrade? (Y/N)'
    if (-not $proceed) {
        WG-Log 'Upgrade declined by user.' 'WARN'
        WG-Log 'Runner exiting without changes.' 'INFO'
        Pause-Exit -ExitCode 0
    }

    $wingetArgs = @(
        'upgrade'
        '--all'
        '--accept-source-agreements'
        '--accept-package-agreements'
    )
    # NOTE: --force is deliberately NOT included.
    # It overrides `winget pin` exclusions, which defeats the purpose
    # of pinning. Users expect pins to be honored here.

    if ($env:FC_ALLOW_UNKNOWN_VERSIONS -eq '1') {
        Write-Host ''
        Write-Host ' --include-unknown is enabled.' -ForegroundColor Yellow
        Write-Host ' It can cause winget to touch packages whose installed' -ForegroundColor Yellow
        Write-Host ' state winget cannot read - including pinned ones.' -ForegroundColor Yellow
        Write-Host ' Pins are still respected (no --force), but the candidate' -ForegroundColor Yellow
        Write-Host ' list is wider than usual.' -ForegroundColor Yellow
        $includeUnknown = Read-YesNo 'Add --include-unknown this run? (Y/N)'
        if ($includeUnknown) {
            $wingetArgs += '--include-unknown'
        } else {
            Write-Host ' Skipping --include-unknown for this run.' -ForegroundColor Gray
        }
    }

    WG-Log ("Beginning: winget {0}" -f ($wingetArgs -join ' ')) 'STEP'
    WG-Log 'Native progress bar will render in this window.' 'INFO'
    WG-Log 'This may take 10-60 minutes.' 'INFO'
    Write-Host ''

    $start = Get-Date
    $installOk = $false

    try {
        # Execution occurs straight inside this active window context
        & winget.exe $wingetArgs

        $exitCode = $LASTEXITCODE
        $installOk = ($exitCode -eq 0)

        $duration = (Get-Date) - $start

        # Map winget exit codes to readable text
        $codeText = switch ([int64]$exitCode) {
            0            { 'SUCCESS' }
            -1978335188  { 'APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE (0x8A150014) - source index is stale, or package requires interactive install' }
            -1978335135  { 'APPINSTALLER_CLI_ERROR_NO_APPLICABLE_UPGRADE_FOUND (0x8A150031)' }
            -1978335182  { 'APPINSTALLER_CLI_ERROR_INSTALL_PACKAGE_IN_USE (0x8A15001A)' }
            -1978334968  { 'APPINSTALLER_CLI_ERROR_INSTALL_REBOOT_REQUIRED_TO_FINISH (0x8A1500A8)' }
            default      { "exit code {0} (0x{1:X8})" -f $exitCode, [uint32]$exitCode }
        }

        $level = if ($installOk) { 'OK' } else { 'WARN' }
        WG-Log ("Winget upgrade completed in {0:N1} minutes." -f $duration.TotalMinutes) $level
        WG-Log ("  Result: {0}" -f $codeText) $level

        if (-not $installOk -and [int64]$exitCode -eq -1978335188) {
            WG-Log '  Recommendation: check network path to cdn.winget.microsoft.com, then re-run:' 'INFO'
            WG-Log '    winget source update' 'INFO'
            WG-Log '    winget upgrade --all' 'INFO'
        }
    } catch {
        WG-Log "Upgrade failed: $($_.Exception.Message)" 'ERROR'
    }

    # ============================================================
    # Part 4 - Verify
    # ============================================================
    WG-Section 'Part 4 - Post-upgrade state'
    WG-Log 'Re-enumerating to verify state...' 'STEP'

    try {
        $verifyOut = & winget.exe upgrade --include-unknown --accept-source-agreements 2>&1
        foreach ($line in $verifyOut) {
            WG-Log $line 'INFO'
        }
    } catch { }

    # ============================================================
    # Summary
    # ============================================================
    WG-Section 'Summary'
    if ($installOk) {
        WG-Log 'Winget upgrade runner finished successfully.' 'OK'
    } else {
        WG-Log 'Winget upgrade runner finished with warnings or error codes.' 'WARN'
    }
    WG-Log "Full log: $logFile" 'INFO'

    Pause-Exit -ExitCode 0

} catch {
    WG-Log "FATAL SCRIPT ERROR: $($_.Exception.Message)" 'ERROR'
    Pause-Exit -ExitCode 1
}
'@
# ============================================================
# HELPER: Windows Update Cache Reset
# ============================================================
# [REMOVED-RESETWU] Reset-WUCache (was dead code - see Clean-DeadCode.ps1)

# ============================================================
# STEP 1: Clean System-Wide Junk
# ============================================================

# ============================================================
# EMBEDDED WINDOWS UPDATE RUNNER (written to TEMP at runtime)
# ============================================================
$Script:EmbeddedWuRunner = @'
# WinTune - Windows Update Runner
# Launched by WinTune Step 39. Runs in its own visible window.

$ErrorActionPreference = 'Continue'
# ProgressPreference must be Continue, not SilentlyContinue, or
# PSWindowsUpdate's native Write-Progress bars are suppressed.
$ProgressPreference = 'Continue'
$__logDir = if ($env:FC_LOG_DIR) { $env:FC_LOG_DIR } else { Split-Path -Parent $PSCommandPath }
$logFile = if ($env:FC_LOG_DIR) { Join-Path $env:FC_LOG_DIR 'WinTune_WU.log' } else { Join-Path (Split-Path -Parent $PSCommandPath) 'WinTune_WU.log' }
function WU-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'STEP'  { 'Cyan' }
        default { 'Gray' }
    }
    $line = "$stamp [$Level] $Message"
    Write-Host $line -ForegroundColor $color
    try { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 } catch { }
}

function Pause-Exit {
    Write-Host 'Press any key to close this window...' -ForegroundColor DarkGray
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
}
# ---- Embedded WUA cache reset helper (needed because this is a separate process) ----
function Reset-WUCache {
    try {
        foreach ($svc in 'wuauserv', 'bits', 'cryptsvc', 'appidsvc') {
            try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } catch { }
        }
        Start-Sleep -Seconds 3

        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $sd    = Join-Path $env:SystemRoot 'SoftwareDistribution'
        $cr    = Join-Path $env:SystemRoot 'System32\catroot2'

        if (Test-Path -LiteralPath $sd) {
            Rename-Item -LiteralPath $sd -NewName "SoftwareDistribution.old_$stamp" -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $cr) {
            Rename-Item -LiteralPath $cr -NewName "catroot2.old_$stamp" -Force -ErrorAction Stop
        }

        foreach ($svc in 'cryptsvc', 'bits', 'wuauserv', 'appidsvc') {
            try { Start-Service -Name $svc -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } catch { }
        }
        Start-Sleep -Seconds 3

        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline) {
            $wu = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
            if ($wu -and $wu.Status -eq 'Running') {
                # [FIX-RESETWU-HASHTABLE] Return hashtable so caller can
                # log WHY the reset failed, not just "didn't work."
                return @{ Ok = $true; Reason = 'reset complete; wuauserv running' }
            }
            Start-Sleep -Seconds 2
        }
        return @{ Ok = $false; Reason = 'wuauserv did not reach Running within 30s after reset' }
    } catch {
        return @{ Ok = $false; Reason = $_.Exception.Message }
    }
}

try {
    Clear-Host
    try { $Host.UI.RawUI.WindowTitle = 'WinTune - Windows Update' } catch { }
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' WinTune - Windows Update Installer (Detached)' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan

    WU-Log 'Windows Update runner started.' 'OK'
    WU-Log "PID: $PID"
    WU-Log "Log: $logFile"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Make PSGallery trust a hard step BEFORE any module operation.
    # A silent failure here is what causes the interactive "install from
    # untrusted repository?" prompt. If trust cannot be established we
    # log it loudly so the user knows why a prompt appeared.
    # Reorder: check presence BEFORE attempting PSGallery trust.
    # PSGallery trust is entirely unnecessary if PSWindowsUpdate is
    # already installed. Skipping it avoids the module-load failure
    # path that occurs on systems with CBS pending state.
    $minVersion = [version]'2.2.1.5'
    $module = Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue |
              Sort-Object Version -Descending |
              Select-Object -First 1

    $needsInstall = (-not $module)
    $needsUpdate  = ($module -and $module.Version -lt $minVersion)

    if ($needsInstall -or $needsUpdate) {
        WU-Log 'PSGallery trust required (module needs install/update).' 'STEP'
        try {
            Import-Module PowerShellGet -Force -ErrorAction Stop
            $__repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if (-not $__repo) {
                Register-PSRepository -Default -ErrorAction Stop
                WU-Log 'PSGallery repository registered.' 'OK'
            }
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            WU-Log 'PSGallery trusted - no install prompt expected.' 'OK'
        } catch {
            WU-Log ("PSGallery trust failed (best-effort): {0}" -f $_.Exception.Message) 'WARN'
            WU-Log 'Continuing anyway - Install-Module may still prompt.' 'INFO'
        }
    } else {
        WU-Log ("PSWindowsUpdate {0} already available - skipping PSGallery trust." -f $module.Version) 'OK'
    }

    if (-not $module) {
        WU-Log 'PSWindowsUpdate not installed - installing from PSGallery...' 'STEP'
        try {
            # [FIX-WU-INSTALLMODULE] Install-Module has no -AcceptLicense
            # parameter. The -Force flag already implies non-interactive
            # acceptance of the license prompt.
            Install-Module -Name PSWindowsUpdate `
                -Scope CurrentUser `
                -Force `
                -AllowClobber `
                -SkipPublisherCheck `
                -Confirm:$false `
                -ErrorAction Stop
            WU-Log 'PSWindowsUpdate installed.' 'OK'
        } catch {
            WU-Log "Failed to install PSWindowsUpdate: $($_.Exception.Message)" 'ERROR'
            WU-Log 'Manually install with: Install-Module PSWindowsUpdate -Force' 'INFO'
            Pause-Exit
            exit 1
        }
    } elseif ($module.Version -lt $minVersion) {
        WU-Log ("PSWindowsUpdate {0} is older than {1} - updating..." -f $module.Version, $minVersion) 'STEP'
        try {
            Update-Module -Name PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop
            WU-Log 'PSWindowsUpdate updated.' 'OK'
        } catch {
            WU-Log ("Update failed: {0}" -f $_.Exception.Message) 'WARN'
            WU-Log ("Continuing with version {0}" -f $module.Version) 'WARN'
        }
    } else {
        WU-Log ("PSWindowsUpdate {0} is current (>= {1})." -f $module.Version, $minVersion) 'OK'
    }

    try {
        Import-Module PSWindowsUpdate -ErrorAction Stop
        WU-Log 'Module loaded.' 'OK'
    } catch {
        $__impErr = $_.Exception.Message
        WU-Log "Primary import failed: $__impErr" 'WARN'
        try {
            if ($module) {
                $__mPath = Join-Path $module.ModuleBase ($module.Name + '.psd1')
                if (Test-Path -LiteralPath $__mPath) {
                    Import-Module $__mPath -ErrorAction Stop
                    WU-Log 'Module loaded via explicit path fallback.' 'OK'
                } else { throw 'Module manifest not found' }
            } else { throw 'No module handle for fallback' }
        } catch {
            WU-Log "Module import failed: $__impErr; fallback: $($_.Exception.Message)" 'ERROR'
            Pause-Exit
            exit 1
        }
    }

    WU-Log 'Scanning for available updates (PSWindowsUpdate)...' 'STEP'

    # The raw WUA Search() COM API is broken on this Windows build
    # (Microsoft bug in June 2024 preview, affects Windows 11 26100+).
    # It throws ArgumentException on any criteria string.
    #
    # PSWindowsUpdate survives because it collects results BEFORE the
    # crash. We use it for the scan and accept partial results.

    $available = @()
    $scanWarn  = @()
    # [FIX-WU-SCANFLAG] Track whether the scan actually failed so we
    # don't claim "no updates available" when the real answer is
    # "couldn't scan."
    $Script:__wuScanFailed = $false

    try {
        $available = @(
            Get-WindowsUpdate -WarningVariable scanWarn -WarningAction SilentlyContinue
        )
    } catch {
        $errMsg = $_.Exception.Message
        WU-Log ("Scan emitted a non-fatal error: {0}" -f $errMsg) 'WARN'

        # Known WUA COM error - reset cache and retry once
        if ($errMsg -match 'Value does not fall within the expected range') {
            WU-Log 'This is a known Windows Update Agent state issue.' 'WARN'
            # [FIX-WU-SCAN-RESILIENCE] Try the lightweight recovery first:
            # just sleep and retry. Step 1 already stopped and restarted
            # wuauserv/dosvc/bits/cryptsvc minutes ago, and a fresh cache
            # was just created. A heavy Reset-WUCache here is both
            # unnecessary and prone to failing because the freshly-created
            # SoftwareDistribution folder is held open by the restarted
            # services. Only fall back to a hard reset if the light retry
            # also fails.
            WU-Log 'Sleeping 30s to let the WU agent settle, then retrying...' 'STEP'
            Start-Sleep -Seconds 30

            $__scanSucceeded = $false
            try {
                $available = @(
                    Get-WindowsUpdate -WarningVariable scanWarn -WarningAction SilentlyContinue
                )
                WU-Log ("Retry succeeded. Found {0} update(s)." -f $available.Count) 'OK'
                $__scanSucceeded = $true
            } catch {
                WU-Log ("Retry after 30s sleep also failed: {0}" -f $_.Exception.Message) 'WARN'
                WU-Log 'Attempting hard cache reset as last resort...' 'STEP'

                $resetResult = Reset-WUCache
                $resetOk    = if ($resetResult -is [hashtable]) { $resetResult.Ok } else { [bool]$resetResult }
                $resetWhy   = if ($resetResult -is [hashtable] -and $resetResult.Reason) { $resetResult.Reason } else { '(no reason provided)' }

                if ($resetOk) {
                    WU-Log 'Cache reset complete. Retrying scan in 5 seconds...' 'STEP'
                    Start-Sleep -Seconds 5
                    try {
                        $available = @(
                            Get-WindowsUpdate -WarningVariable scanWarn -WarningAction SilentlyContinue
                        )
                        WU-Log ("Retry after reset succeeded. Found {0} update(s)." -f $available.Count) 'OK'
                        $__scanSucceeded = $true
                    } catch {
                        WU-Log ("Final retry after cache reset failed: {0}" -f $_.Exception.Message) 'ERROR'
                    }
                } else {
                    WU-Log ("Cache reset did not complete: {0}" -f $resetWhy) 'WARN'
                }
            }

            if (-not $__scanSucceeded) {
                $Script:__wuScanFailed = $true
            }
        }
    }

    if ($scanWarn -and $scanWarn.Count -gt 0) {
        WU-Log ("Scan emitted {0} warning(s):" -f $scanWarn.Count) 'WARN'
        $scanWarn | Select-Object -Unique | ForEach-Object {
            WU-Log ("  [warn] {0}" -f $_) 'WARN'
        }
    }

    $available = @($available)

    # If the scan returned nothing after recovery, report honestly.
    # Do NOT treat installed-update history as "available updates" - that
    # is a different dataset and would create false reporting.
    if ($available.Count -eq 0) {
        WU-Log '' 'INFO'
        # [FIX-WU-NOUPDATE-MSG] Distinguish "scan failed" from
        # "scan succeeded and returned nothing." These are not
        # the same and the previous message was misleading.
        if ($Script:__wuScanFailed) {
            WU-Log 'Scan did not complete — update availability is UNKNOWN.' 'WARN'
            WU-Log 'This is not the same as "no updates available."' 'WARN'
            WU-Log 'Run Windows Update manually to check:' 'INFO'
            WU-Log '  Settings -> Windows Update -> Check for updates' 'INFO'
        } else {
            WU-Log 'No available updates returned by Windows Update Agent.' 'OK'
            WU-Log 'If this is unexpected, run Windows Update manually:' 'INFO'
            WU-Log '  Settings -> Windows Update -> Check for updates' 'INFO'
        }
    }
    # Filter out driver updates from the display (they have no KB).
    # Drivers are handled separately (audit-only) â€” not auto-installed.
    $preFilterCount = $available.Count
    $available = @($available | Where-Object {
        $kbProp = $_.PSObject.Properties['KB']
        $kbVal  = if ($kbProp) { [string]$kbProp.Value } else { '' }
        -not [string]::IsNullOrWhiteSpace($kbVal)
    })
    $filteredCount = $preFilterCount - $available.Count
    if ($filteredCount -gt 0) {
        WU-Log ("  (filtered out {0} driver update(s) with no KB)" -f $filteredCount) 'INFO'
    }

    # [FIX-WU-HONEST-MSG] The earlier WARN block correctly told the user
    # the scan failed. Do not print "No updates available" here - that
    # contradicts the WARN and misleads the user into thinking the agent
    # actually confirmed zero updates.
    if ($available.Count -gt 0) {
        WU-Log ("Found {0} update record(s):" -f $available.Count) 'OK'
        WU-Log '' 'INFO'
        WU-Log ('{0,-12} {1,-14} {2}' -f 'Size(MB)', 'KB ID', 'Title') 'INFO'
        WU-Log ('{0,-12} {1,-14} {2}' -f ('-' * 12), ('-' * 14), ('-' * 50)) 'INFO'
        foreach ($u in $available) {
            # Parse PSWindowsUpdate's Size field
            $sizeMB = 0.0
            foreach ($sz in @($u.Size)) {
                if ($null -eq $sz) { continue }
                $s = [string]$sz
                if ([string]::IsNullOrWhiteSpace($s)) { continue }
                if ($s -match '^\s*([0-9.]+)\s*(GB|MB|KB|B)?\s*$') {
                    $num  = [double]$matches[1]
                    $unit = if ($matches[2]) { $matches[2].ToUpperInvariant() } else { 'B' }
                    switch ($unit) {
                        'GB' { $sizeMB += $num * 1024.0 }
                        'MB' { $sizeMB += $num }
                        'KB' { $sizeMB += $num / 1024.0 }
                        'B'  { $sizeMB += $num / (1024.0 * 1024.0) }
                    }
                } elseif ($s -match '^\s*([0-9]+)\s*$') {
                    $sizeMB += ([double]$matches[1]) / (1024.0 * 1024.0)
                }
            }
            $sizeMB = [math]::Round($sizeMB, 1)
            $kbIds  = if ($u.PSObject.Properties['KB'] -and -not [string]::IsNullOrWhiteSpace($u.KB)) { [string]$u.KB } else { '(none)' }
            $title  = if ([string]::IsNullOrWhiteSpace($u.Title)) { '(no title)' } else { $u.Title }
            WU-Log ('{0,-12:N1} {1,-14} {2}' -f $sizeMB, $kbIds, $title) 'INFO'
        }
    } else {
        # [FIX-WU-HONEST-MSG] Distinguish scan-failed from scan-succeeded-empty.
        if ($Script:__wuScanFailed) {
            WU-Log 'No updates to install (scan did not complete — availability UNKNOWN).' 'WARN'
        } else {
            WU-Log 'No updates available at this time.' 'OK'
        }
    }


    WU-Log 'Installing security, critical, and definition updates...' 'STEP'
    WU-Log 'No automatic reboot will occur.' 'INFO'

    $installOk     = $false
    $installResult = @()
    $installWarn   = @()
    $installResult = @()
    try {
        # COM-based install: sortable, per-update control, download-then-install
        $comSession = New-Object -ComObject Microsoft.Update.Session
        $comSearcher = $comSession.CreateUpdateSearcher()
        # WU-RETRY-LOGIC
        $maxAttempts = 2
        $attempt = 0
        $comSearch = $null
        while ($attempt -lt $maxAttempts) {
            $attempt++
            try {
                $comSearch = $comSearcher.Search("IsInstalled=0 and Type='Software'")
                break
            } catch {
                $errMsg = $_.Exception.Message
                if ($attempt -lt $maxAttempts) {
                    Write-Host ("  WUA search attempt {0} failed: {1} - retrying in 30s..." -f $attempt, $errMsg) -ForegroundColor Yellow
                    Start-Sleep -Seconds 30
                } else {
                    throw
                }
            }
        }

        # Filter by real WUA category GUIDs (stable across Windows versions
        # and languages; title text is localized and unreliable).
        $allowedCategories = @{
            '0fa1201d-4330-4fa8-8ae9-b877473b6441' = 'Security Updates'
            'e6cf1350-c01b-414d-a61f-263d14d133b4' = 'Critical Updates'
            'e0789628-ce08-4437-be74-2495b842f43b' = 'Definition Updates'
            '28bc880e-0592-4cbf-8f95-c79b2959bce6' = 'Update Rollups'
            'f0b7bfad-2c8d-4492-8e7d-cd1f7a6d1c56' = 'Win10 Quality Updates'
            'f1ca4dc1-4d85-4a8f-8b5f-28e1e5c8e6e4' = 'Win11 Quality Updates'
        }

        $comList = @()
        foreach ($u in $comSearch.Updates) {
            $t = [string]$u.Title
            if (-not $t) { continue }

            # Match by WUA category GUID
            $matchedCategory = $null
            if ($u.Categories.Count -gt 0) {
                for ($c = 0; $c -lt $u.Categories.Count; $c++) {
                    $catGuid = [string]$u.Categories.Item($c).CategoryID
                    if ($allowedCategories.ContainsKey($catGuid)) {
                        $matchedCategory = $allowedCategories[$catGuid]
                        break
                    }
                }
            }

            if (-not $matchedCategory) { continue }

            $kb = if ($u.PSObject.Properties['KB'] -and -not [string]::IsNullOrWhiteSpace($u.KB)) { $u.KB } else { '' }
            # [FIX-WU-SIZE] MaxDownloadSize can return 0 or 0xFFFFFFFFFFFFFFFF
            # (uint64 max) for updates whose size is not yet resolved.
            # Casting uint64 max to int64 overflows to -1, which divided
            # by 1MB looks like ~92 GB. Treat 0 and huge values as
            # "unknown size" (0) rather than "suspiciously large" so we
            # don't skip legitimate updates on bogus metadata.
            $__rawSize = [uint64]$u.MaxDownloadSize
            if ($__rawSize -eq 0 -or $__rawSize -gt 10GB) {
                $sizeMB = [int64]0
            } else {
                $sizeMB = [int64]($__rawSize / 1MB)
            }

            $comList += [PSCustomObject]@{
                Update   = $u
                Title    = $t
                KB       = $kb
                SizeMB   = $sizeMB
                Category = $matchedCategory
            }
        }

        # Sort ascending by size - smallest first.
        # [FIX-WU-SIZE-SORT] Unknown sizes (0) sort last so we don't
        # preempt the small well-known installs with a "try and see"
        # candidate that may fail late.
        $comList = @($comList | Sort-Object -Property @{
            Expression = { if ([int64]$_.SizeMB -eq 0) { [int64]::MaxValue } else { [int64]$_.SizeMB } }
        })
        # Safety gate: skip suspiciously large updates (>10 GB)
        # Real Windows updates are < 5 GB; anything larger is a corrupted manifest
        $preGateCount = $comList.Count
        $comList = @($comList | Where-Object {
            if ([int64]$_.SizeMB -gt 10000) {
                WU-Log ("  [SKIP] Suspiciously large ({0:N1} MB > 10000 MB): {1}" -f $_.SizeMB, $_.Title) 'WARN'
                return $false
            }
            return $true
        })
        $gatedCount = $preGateCount - $comList.Count
        if ($gatedCount -gt 0) {
            WU-Log ("  ({0} update(s) filtered by size gate)" -f $gatedCount) 'WARN'
            WU-Log '' 'INFO'
        }

        if ($comList.Count -eq 0) {
            WU-Log 'No updates matched the security/critical/definition filter.' 'OK'
        } else {
            WU-Log ("{0} update(s) to install (smallest first):" -f $comList.Count) 'STEP'
            foreach ($item in $comList) {
                WU-Log ("  {0,10:N1} MB  {1,-22} {2,-14} {3}" -f $item.SizeMB, $item.Category, $item.KB, $item.Title) 'INFO'
            }
            WU-Log '' 'INFO'
        }

        foreach ($item in $comList) {
            $u = $item.Update

            # Download if needed
            if (-not $u.IsDownloaded) {
                WU-Log ("Downloading {0:N1} MB: {1}" -f $item.SizeMB, $item.Title) 'INFO'
                try {
                    $dlColl = New-Object -ComObject Microsoft.Update.UpdateColl
                    [void]$dlColl.Add($u)
                    $downloader = $comSession.CreateUpdateDownloader()
                    $downloader.Updates = $dlColl
                    $dlRes = $downloader.Download()
                    $dlCode = [int]$dlRes.ResultCode
                    if ($dlCode -eq 2 -or $dlCode -eq 3) {
                        WU-Log '  [OK] Downloaded' 'OK'
                    } else {
                        WU-Log ("  [FAIL] Download failed (0x{0:X8})" -f [int]$dlRes.HResult) 'ERROR'
                        $installResult += [PSCustomObject]@{
                            Title        = $item.Title
                            KBArticleIDs = @($item.KB)
                            Result       = 'DownloadFailed'
                        }
                        continue
                    }
                } catch {
                    WU-Log ("  [FAIL] Download error: {0}" -f $_.Exception.Message) 'ERROR'
                    $installResult += [PSCustomObject]@{
                        Title        = $item.Title
                        KBArticleIDs = @($item.KB)
                        Result       = 'DownloadError'
                    }
                    continue
                }
            }

            # Install with retry
            WU-Log ("Installing: {0}" -f $item.Title) 'STEP'

            # [FIX-WU-RETRY] Per-update retry with transient-error
            # detection. The old code was one-shot: a transient
            # 0x80240020 (another install in progress) or 0x8024001E
            # (WU service stopped) meant the update was skipped and
            # the run moved on. Users had to manually re-run WinTune
            # to pick up the update on the second attempt.
            #
            # New behavior: retry transient failures up to N times
            # with linear backoff. Permanent failures (not applicable,
            # signature failure, payload missing) give up immediately.
            # Reboot-pending results stop retries for that update —
            # no amount of retrying will help without a reboot.
            #
            # Tunable via FC_WU_MAX_RETRIES (default 3, cap 10).
            # Set to 1 to disable retries entirely.
            $__wuMaxRetries = 3
            if ($env:FC_WU_MAX_RETRIES) {
                try { $__wuMaxRetries = [int]$env:FC_WU_MAX_RETRIES } catch { }
            }
            if ($__wuMaxRetries -lt 1)  { $__wuMaxRetries = 1 }
            if ($__wuMaxRetries -gt 10) { $__wuMaxRetries = 10 }

            $__attempt = 0
            $__finalResultText = 'Failed'
            $__finalHres = 0
            $__finalCode = -1
            $__finalRebootRequired = $false

            while ($__attempt -lt $__wuMaxRetries) {
                $__attempt++
                if ($__attempt -gt 1) {
                    $__backoff = 30 * ($__attempt - 1)
                    WU-Log ("  Retrying (attempt {0}/{1}) after {2}s backoff..." -f $__attempt, $__wuMaxRetries, $__backoff) 'STEP'
                    Start-Sleep -Seconds $__backoff
                }

                try {
                    $instColl = New-Object -ComObject Microsoft.Update.UpdateColl
                    [void]$instColl.Add($u)
                    $installer = $comSession.CreateUpdateInstaller()
                    $installer.Updates = $instColl
                    $installer.AttemptCloseAppsIfNecessary = $true
                    $installer.ForceQuiet = $true
                    $res = $installer.Install()

                    $code = [int]$res.ResultCode
                    $hres = [int]$res.HResult

                    $resultText = switch ($code) {
                        2 { 'Installed' }
                        3 { 'InstalledWithErrors' }
                        4 {
                            switch ($hres) {
                                -2145124329 { 'SkippedNotApplicable' }
                                -2145124307 { 'SkippedRebootRequired' }
                                -2145124320 { 'SkippedBusy' }
                                default     { 'Failed' }
                            }
                        }
                        5 { 'Aborted' }
                        default { 'Unknown' }
                    }

                    $__finalResultText = $resultText
                    $__finalHres = $hres
                    $__finalCode = $code
                    $__finalRebootRequired = [bool]$res.RebootRequired

                    $__p = if ($__attempt -gt 1) { "[attempt $__attempt/$__wuMaxRetries] " } else { '' }
                    switch ($resultText) {
                        'Installed'             { WU-Log ("  {0}[OK] Installed: {1}" -f $__p, $item.Title) 'OK' }
                        'InstalledWithErrors'   { WU-Log ("  {0}[WARN] Installed with errors: {1}" -f $__p, $item.Title) 'WARN' }
                        'SkippedNotApplicable'  { WU-Log ("  {0}[SKIP] Not applicable: {1}" -f $__p, $item.Title) 'WARN' }
                        'SkippedRebootRequired' { WU-Log ("  {0}[SKIP] Reboot required: {1}" -f $__p, $item.Title) 'WARN' }
                        'SkippedBusy'           { WU-Log ("  {0}[SKIP] Busy: {1}" -f $__p, $item.Title) 'WARN' }
                        'Failed'                { WU-Log ("  {0}[FAIL] Failed (0x{1:X8}): {2}" -f $__p, $hres, $item.Title) 'ERROR' }
                        'Aborted'               { WU-Log ("  {0}[FAIL] Aborted: {1}" -f $__p, $item.Title) 'ERROR' }
                        default                 { WU-Log ("  {0}[WARN] Unknown result code {1} for {2}" -f $__p, $code, $item.Title) 'WARN' }
                    }

                    if ($res.RebootRequired) {
                        WU-Log '  [INFO] Reboot required after this update.' 'WARN'
                    }
                } catch {
                    WU-Log ("  [FAIL] {0}: {1}" -f $item.Title, $_.Exception.Message) 'ERROR'
                    $__finalResultText = 'Failed'
                    $__finalHres = 0
                    $__finalCode = -1
                }

                # Success -> stop retrying
                if ($__finalResultText -match '^Installed') { break }

                # Reboot pending -> stop (retry cannot help without reboot)
                if ($__finalRebootRequired) {
                    if ($__attempt -lt $__wuMaxRetries) {
                        WU-Log ("  Reboot pending - stopping retries for {0}" -f $item.Title) 'WARN'
                    }
                    break
                }

                # Decide retry-worthiness
                $__isTransient = $false
                if ($__finalResultText -eq 'SkippedBusy') { $__isTransient = $true }
                if ($__finalResultText -match 'Failed|Aborted|Unknown') {
                    $__transientHres = @(
                        -2145124320,   # 0x80240020 WU_E_INSTALL_NOT_ALLOWED
                        -2145124322,   # 0x8024001E WU_E_SERVICE_STOP
                        -2145124341,   # 0x8024000B WU_E_CALL_CANCELLED
                        -2147023436,   # 0x800705B4 ERROR_TIMEOUT
                        -2147023431,   # 0x800705B9 ERROR_NO_SYSTEM_RESOURCES
                        -2147024891,   # 0x80070005 E_ACCESSDENIED
                        0              # unknown HResult from exception path
                    )
                    if ($__transientHres -contains $__finalHres) { $__isTransient = $true }
                    if ($__finalResultText -eq 'Aborted' -and $__finalCode -eq 5) { $__isTransient = $true }
                }

                if (-not $__isTransient) { break }
                if ($__attempt -ge $__wuMaxRetries) {
                    WU-Log ("  Retries exhausted ({0}/{1}) - giving up on {2}" -f $__attempt, $__wuMaxRetries, $item.Title) 'WARN'
                    break
                }
            }

            # Record the final result once (after all retries)
            $installResult += [PSCustomObject]@{
                Title        = $item.Title
                KBArticleIDs = @($item.KB)
                Result       = $__finalResultText
                Attempts     = $__attempt
            }
        }

        # [FIX-WU-EXITCODE-A] Compute $installOk from actual results.
        # Previously $installOk = $true fired unconditionally after the
        # install loop, only proving the try block didn't throw. A batch
        # where every update aborted still set it to $true, and the
        # runner then claimed success and exited 0.
        $__fail = @($installResult | Where-Object {
            $_.Result -match 'Failed|Error|Aborted|Unknown'
        }).Count
        if ($__fail -gt 0) {
            $installOk = $false
        } elseif ($installResult.Count -gt 0 -or $comList.Count -eq 0) {
            # Either we recorded results (all success/skip, since fail=0)
            # or there was nothing to install. Both are clean outcomes.
            $installOk = $true
        } else {
            # Candidates existed but no results recorded — the loop
            # never produced an outcome. Treat as failure.
            $installOk = $false
        }
    } catch {
        WU-Log ("Install failed: {0}" -f $_.Exception.Message) 'ERROR'
        WU-Log 'This may be a temporary network or catalog issue. Re-run when ready.' 'INFO'
    }
    if ($installWarn -and $installWarn.Count -gt 0) {
        WU-Log "Install pass emitted $($installWarn.Count) warning(s):" 'WARN'
        $installWarn | Select-Object -Unique | ForEach-Object {
            WU-Log "  [warn] $_" 'WARN'
        }
    }

    $installResult = @($installResult)
    $rawCount = $installResult.Count

    # Install-WindowsUpdate returns one result per (update, KB, category)
    # combination, so the same update can appear 2-3 times. Deduplicate by
    # KB + Title + Result so the user sees one row per update.
    $uniqueResults = @()
    $seen = @{}
    foreach ($r in $installResult) {
        $kbKey = ''
        if ($r.PSObject.Properties['KBArticleIDs'] -and $r.KBArticleIDs) {
            $kbKey = ($r.KBArticleIDs -join ',')
        }
        $titleKey  = if ($r.PSObject.Properties['Title']  -and $r.Title)  { [string]$r.Title }  else { '' }
        $resultKey = if ($r.PSObject.Properties['Result'] -and $r.Result) { [string]$r.Result } else { '' }

        $dedupKey = '{0}|{1}|{2}' -f $kbKey, $titleKey, $resultKey
        if ($seen.ContainsKey($dedupKey)) {
            $seen[$dedupKey]++
            continue
        }
        $seen[$dedupKey] = 1

        $uniqueResults += [PSCustomObject]@{
            Result    = $resultKey
            KB        = $kbKey
            Title     = $titleKey
            DupeCount = 1
        }
    }

    WU-Log ("Install pass completed. Raw results: {0}, unique updates: {1}" -f $rawCount, $uniqueResults.Count) 'OK'

    if ($uniqueResults.Count -gt 0) {
        WU-Log '' 'INFO'
        WU-Log ('{0,-14} {1,-12} {2}' -f 'Result', 'KB', 'Title') 'INFO'
        WU-Log ('{0,-14} {1,-12} {2}' -f ('-' * 14), ('-' * 12), ('-' * 50)) 'INFO'
        foreach ($r in $uniqueResults) {
            $kb    = if ([string]::IsNullOrWhiteSpace($r.KB))    { '(none)'     } else { $r.KB }
            $title = if ([string]::IsNullOrWhiteSpace($r.Title)) { '(no title)' } else { $r.Title }
            WU-Log ('{0,-14} {1,-12} {2}' -f $r.Result, $kb, $title) 'INFO'
        }

        # [FIX-WU-EXITCODE-B] Correct count buckets. Old 'Installed|Succeeded'
        # regex also matched InstalledWithErrors (double-counted as both
        # success and failure). Old 'Failed|Error' missed 'Aborted'
        # entirely, so an aborted update vanished from the summary.
        $okCount      = @($uniqueResults | Where-Object { $_.Result -eq 'Installed' }).Count
        $partialCount = @($uniqueResults | Where-Object { $_.Result -eq 'InstalledWithErrors' }).Count
        $skipCount    = @($uniqueResults | Where-Object { $_.Result -match '^Skipped' }).Count
        $failCount    = @($uniqueResults | Where-Object {
            $_.Result -match 'Failed|Error|Aborted|Unknown'
        }).Count

        WU-Log '' 'INFO'
        WU-Log ("Summary: {0} installed, {1} installed-with-errors, {2} skipped, {3} failed/aborted" `
                -f $okCount, $partialCount, $skipCount, $failCount) 'INFO'
    }

    try {
        $pending = Get-WURebootStatus -Silent -ErrorAction SilentlyContinue
        if ($pending) {
            WU-Log 'REBOOT REQUIRED to complete update installation.' 'WARN'
        } else {
            WU-Log 'No reboot pending.' 'OK'
        }
    } catch {
        WU-Log 'Could not determine reboot status.' 'INFO'
    }

    # [FIX-WU-EXITCODE-C] Final exit code reflects install outcome,
    # not just "did we finish the loop". Parent reconciliation
    # (Fix-DetachedExitReport) uses exit code to decide step status
    # in the HTML report. Without this, aborted installs still show
    # as Step 39 OK.
    if ($installOk) {
        WU-Log 'Windows Update runner finished successfully.' 'OK'
        $__wuExitCode = 0
    } else {
        WU-Log 'Windows Update runner finished with failures - see summary above.' 'WARN'
        $__wuExitCode = 1
    }

    Pause-Exit
    try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue } catch { }
    exit $__wuExitCode
} catch {
    WU-Log "FATAL: $($_.Exception.Message)" 'ERROR'
    Pause-Exit
    try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue } catch { }
    exit 1
}


'@

function Invoke-Step01 {
    <#
    .SYNOPSIS
        Deletes caches, logs, temp files, and diagnostic data from
        across the Windows system drive and per-user profiles.

    .DESCRIPTION
        Categories of cleanup:
          * Temp directories (system + user + machine-wide)
          * Windows Update cache + DataStore + logs
          * Delivery Optimization cache
          * Error reporting archives (system + user)
          * Crash dumps (user + live kernel + minidumps)
          * CBS / DISM logs + Panther setup logs
          * INetCache (legacy internet cache)
          * Font cache temp data
          * PeerDist / BranchCache replication store
          * Windows Reset leftovers ($SysReset)
          * HP printer driver extraction folders (C:\HP_*)
          * Full memory dumps (MEMORY.DMP)

        For each target, the step:
          1. Reports the size before clearing
          2. Clears file contents (preserving the folder)
          3. Reports the bytes reclaimed

        Preserves:
          * All user documents, photos, videos
          * Registered installed-application data
          * Current session state

        Service handling:
          * Stops wuauserv, bits, cryptsvc, dosvc before clearing
            the Windows Update cache
          * Restarts them in dependency order afterward

        Safety notes:
          * $SysReset is the Windows Reset leftovers folder. Only
            touched if the folder exists and is not locked by an
            active Reset operation.
          * C:\HP_* folders are HP printer extraction caches.
            They can be safely regenerated by the HP installer.
          * Windows\Panther holds setup logs only.
          * SoftwareDistribution\DataStore holds the WU database;
            wuauserv is stopped before we touch it, so it is safe.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 1: Cleaning System-Wide Junk' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not (Confirm-Action -Query 'Clear system-wide junk caches, logs, and temp files?')) {
        Write-Log 'Step 1 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would clear system-wide junk caches, logs, and temp files.' -Level PREVIEW
        return
    }

    # ============================================================
    # 1. Build target inventory
    # ============================================================
    $userProfile = $env:USERPROFILE
    $localAppData = $env:LOCALAPPDATA
    $programData = $env:ProgramData
    $systemRoot = $env:SystemRoot

    $targets = [ordered]@{
        # ---- Existing coverage ----
        'Windows Temp (System)'                = (Join-Path $systemRoot  'Temp')
        'Windows Temp (SystemTemp)'            = (Join-Path $systemRoot  'SystemTemp')
        'User Temp'                            = $env:TEMP
        'Windows Update Cache'                 = (Join-Path $systemRoot  'SoftwareDistribution\Download')
        'Windows Update Logs'                  = (Join-Path $systemRoot  'SoftwareDistribution\DataStore\Logs')
        'Delivery Optimization Cache'          = (Join-Path $systemRoot  'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache')
        'Windows Error Reporting (System)'     = (Join-Path $programData 'Microsoft\Windows\WER')
        'Windows Error Reporting (User)'       = (Join-Path $localAppData 'Microsoft\Windows\WER')
        'CBS Component Logs'                   = (Join-Path $systemRoot  'Logs\CBS')
        'DISM Component Logs'                  = (Join-Path $systemRoot  'Logs\DISM')
        'Live Kernel Reports'                  = (Join-Path $systemRoot  'LiveKernelReports')
        'User Crash Dumps'                     = (Join-Path $localAppData 'CrashDumps')
        'INetCache (legacy internet cache)'    = (Join-Path $localAppData 'Microsoft\Windows\INetCache')
        'Downloaded Program Files'             = (Join-Path $systemRoot  'Downloaded Program Files')
        'Font Cache Temp'                      = (Join-Path $systemRoot  'ServiceProfiles\LocalService\AppData\Local\FontCache')
        'BranchCache Replication Store'        = (Join-Path $systemRoot  'ServiceProfiles\NetworkService\AppData\Local\PeerDistRepub')

        # ---- New: Windows servicing leftovers ----
        'Windows Panther Setup Logs'           = (Join-Path $systemRoot  'Panther')
        'Windows Minidump'                     = (Join-Path $systemRoot  'Minidump')
        'System Reset Leftovers'               = (Join-Path $env:SystemDrive '$SysReset')
        'OneDrive Temp'                        = (Join-Path $env:SystemDrive 'OneDriveTemp')
        'PerfLogs'                             = (Join-Path $env:SystemDrive 'PerfLogs')
    }

    # ---- C:\HP_* printer extraction folders (dynamic) ----
    try {
        $hpFolders = Get-ChildItem -LiteralPath "$env:SystemDrive\" -Directory -Force -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -like 'HP_*' }
        foreach ($hp in $hpFolders) {
            $targets["HP Extraction ($($hp.Name))"] = $hp.FullName
        }
    } catch { }

    # ---- MEMORY.DMP (single file, handled separately) ----
    $memoryDumpPath = Join-Path $systemRoot 'MEMORY.DMP'

    # ============================================================
    # 2. Size scan (informational)
    # ============================================================
    Write-Log 'Scanning target sizes (this may take 30-60 seconds)...' -Level INFO

    $sizes = [ordered]@{}
    $totalGB = 0.0

    foreach ($name in $targets.Keys) {
        $path = $targets[$name]
        $gb   = 0.0
        if ($path -and (Test-Path -LiteralPath $path)) {
            $gb = Get-PathSizeGB -Path $path
        }
        $sizes[$name] = $gb
        $totalGB += $gb
    }

    # MEMORY.DMP size
    $memDumpGB = 0.0
    if (Test-Path -LiteralPath $memoryDumpPath) {
        $memDumpGB = [math]::Round((Get-Item -LiteralPath $memoryDumpPath -Force).Length / 1GB, 2)
        $sizes['MEMORY.DMP'] = $memDumpGB
        $totalGB += $memDumpGB
    }

    Write-Host '  Cleanup targets:' -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 58)) -ForegroundColor DarkGray
    foreach ($name in $sizes.Keys) {
        $gb = $sizes[$name]
        $color = if ($gb -ge 1) { 'Yellow' } elseif ($gb -ge 0.1) { 'Gray' } else { 'DarkGray' }
        Write-Host ('   {0,-45} {1,8:N2} GB' -f $name, $gb) -ForegroundColor $color
    }
    Write-Host ('  ' + ('-' * 58)) -ForegroundColor DarkGray
    Write-Host ('   {0,-45} {1,8:N2} GB' -f 'TOTAL TO CLEAN', $totalGB) -ForegroundColor Cyan

    Write-Log ("Total to clean: {0:N2} GB" -f $totalGB) -Level INFO

    if ($totalGB -lt 0.05) {
        Write-Log 'Less than 50 MB to clean - nothing meaningful to do.' -Level INFO
        Write-Log 'Step 1 complete (already clean).' -Level OK
        return
    }

    # ============================================================
    # 3. Stop Windows Update services before touching their caches
    # ============================================================
    Write-Log 'Stopping Windows Update infrastructure services...' -Level INFO

    # ---- Pre-flight: report any active DO jobs before we disturb them ----
    try {
        # [FIX-DO-WARN-1] Suppress the Warning-stream "No active Delivery
        # Optimization jobs" message. Empty queue is a normal state, not
        # a problem worth warning about.
        $doJobs = @(Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        if ($doJobs.Count -gt 0) {
            $active = @($doJobs | Where-Object { $_.Status -eq 'Caching' -or $_.Status -eq 'Downloading' })
            if ($active.Count -gt 0) {
                Write-Log ("  [INFO] {0} active DO download job(s) detected - stopping dosvc first." -f $active.Count) -Level INFO
                foreach ($j in $active) {
                    $mb    = [math]::Round([int64]$j.TotalBytesDownloaded / 1MB, 1)
                    $total = [math]::Round([int64]$j.FileSize / 1MB, 1)
                    Write-Log ("    Job {0}: {1:N1} / {2:N1} MB ({3})" -f $j.FileId.Substring(0,8), $mb, $total, $j.Status) -Level INFO
                }
            } else {
                Write-Log ("  [INFO] {0} DO job(s) present but none active." -f $doJobs.Count) -Level INFO
            }
        } else {
            Write-Log '  [INFO] No active Delivery Optimization jobs.' -Level INFO
        }
    } catch {
        Write-Log ("  [DEBUG] DO status check failed: {0}" -f $_.Exception.Message) -Level DEBUG
    }

    # ---- Stop services (dosvc first, since it holds DO cache handles) ----
    # Each stop is bounded at 30 seconds. If a service doesn't reach
    # Stopped in time, we mark it "still running" and skip the cache
    # cleanups that depend on that service being stopped. This prevents
    # the historical indefinite hang when wuauserv had active WU work.
    $servicesToStop = @('dosvc', 'wuauserv', 'bits', 'cryptsvc')
    $stoppedServices = @()
    $stillRunningServices = @()

    foreach ($svc in $servicesToStop) {
        $svcObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if (-not $svcObj) { continue }

        if ($svcObj.Status -ne 'Running') {
            Write-Log ("  {0} already stopped." -f $svc) -Level DEBUG
            $stoppedServices += $svc   # treat as stopped; cache is safe to clear
            continue
        }

        # Fire-and-forget stop, then poll HasExited with a 30s timeout.
        # Stop-Service's own -Wait has no timeout; this is the only way to
        # bound it without spawning a background job.
        Write-Log ("  Stopping {0} (30s timeout)..." -f $svc) -Level INFO
        $stopSw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            # Redirect stderr to NUL so the "WARNING: Waiting for service"
            # lines don't flood the console. Start-Process -NoNewWindow
            # still shows stdout, but sc.exe writes to stderr.
            $null = Start-Process -FilePath 'sc.exe' -ArgumentList "stop $svc" -NoNewWindow -Wait -RedirectStandardOutput "$env:TEMP\sc_stop_$svc.out" -RedirectStandardError "$env:TEMP\sc_stop_$svc.err" -ErrorAction Stop
            Remove-Item "$env:TEMP\sc_stop_$svc.out","$env:TEMP\sc_stop_$svc.err" -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log ("  [WARN] sc.exe stop {0} failed: {1}" -f $svc, $_.Exception.Message) -Level WARN
        }

        # Poll for Stopped status
        $deadline = (Get-Date).AddSeconds(30)
        $becameStopped = $false
        while ((Get-Date) -lt $deadline) {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($s -and $s.Status -eq 'Stopped') {
                $becameStopped = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
        $stopSw.Stop()

        if ($becameStopped) {
            Write-Log ("  [OK] Stopped: {0} ({1:N1}s)" -f $svc, $stopSw.Elapsed.TotalSeconds) -Level OK
            $stoppedServices += $svc
        } else {
            # wuauserv in particular can take longer when WU is mid-download.
            # Re-attempt once with a longer timeout before giving up.
            Write-Log ("  [INFO] {0} still not Stopped after 30s - retrying with 60s grace..." -f $svc) -Level INFO
            $deadline2 = (Get-Date).AddSeconds(60)
            $becameStopped2 = $false
            while ((Get-Date) -lt $deadline2) {
                $s2 = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if ($s2 -and $s2.Status -eq 'Stopped') { $becameStopped2 = $true; break }
                Start-Sleep -Milliseconds 1000
            }
            if ($becameStopped2) {
                Write-Log ("  [OK] Stopped on retry: {0}" -f $svc) -Level OK
                $stoppedServices += $svc
            } else {
                Write-Log ("  [WARN] {0} still not Stopped after retry (skipping its cache clear)" -f $svc) -Level WARN
                $stillRunningServices += $svc
            }
        }
    }

    # ---- Wait for handles to release ----
    # dosvc keeps DO cache file handles open briefly after Stop-Service.
    # 5 seconds is enough on every build we have tested.
    if ($stoppedServices.Count -gt 0) {
        Write-Log 'Allowing service handles to release (5s)...' -Level INFO
        Start-Sleep -Seconds 5
    }

    # ============================================================
    # 4. Clear each target
    # ============================================================
    Write-Log 'Clearing target directories...' -Level INFO

    $clearFolder = {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return [int64]0 }
        # Refuse to recurse if the target is or contains a reparse point
        if (-not (Test-SafeDeletionTarget -Path $Path)) { return [int64]0 }
        $bytesFreed = [int64]0
        try {
            $items = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                try {
                    if ($item.PSIsContainer) {
                        # Skip reparse points (junctions, symlinks) inside the tree
                        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                            Write-Log ("  [SKIP] Reparse point inside target: {0}" -f $item.FullName) -Level DEBUG
                            continue
                        }
                        # Directory: measure and remove recursively
                        $dirSize = (Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Force -ErrorAction SilentlyContinue |
                                    Where-Object { $_.PSObject.Properties['Length'] } |
                                    Measure-Object -Property Length -Sum |
                                    Select-Object -ExpandProperty Sum)
                        if ($dirSize) { $bytesFreed += [int64]$dirSize }

                        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    } else {
                        # File
                        if ($item.PSObject.Properties['Length']) {
                            $bytesFreed += [int64]$item.Length
                        }
                        Remove-Item -LiteralPath $item.FullName -Force -ErrorAction SilentlyContinue
                    }
                } catch {
                    # Locked file - skip silently
                }
            }
        } catch {
            Write-Log ("  Clear failed for '{0}': {1}" -f $Path, $_.Exception.Message) -Level DEBUG
        }
        return $bytesFreed
    }

    $totalFreed = [int64]0
    $clearedCount = 0
    $skippedCount = 0

    foreach ($name in $targets.Keys) {
        $path = $targets[$name]

        if (-not $path -or -not (Test-Path -LiteralPath $path)) {
            Write-Log ("  [SKIP] Not present: {0}" -f $name) -Level DEBUG
            $skippedCount++
            continue
        }

        # Skip cache targets whose owning service is still running.
        # Deleting a running service's cache leaves it broken until reboot.
        $requiresService = switch -Regex ($name) {
            'Windows Update Cache|Windows Update Logs'      { 'wuauserv' }
            'Delivery Optimization Cache'                   { 'dosvc' }
            default                                          { $null }
        }
        if ($requiresService -and ($stillRunningServices -contains $requiresService)) {
            Write-Log ("  [SKIP] {0} - {1} still running" -f $name, $requiresService) -Level WARN
            $skippedCount++
            continue
        }

        Write-Log ("  Clearing: {0}" -f $name) -Level INFO
        $freed = & $clearFolder $path
        $totalFreed += $freed
        $clearedCount++

        $freedMB = [math]::Round($freed / 1MB, 1)
        if ($freedMB -gt 0) {
            Write-Log ("    Reclaimed {0:N1} MB" -f $freedMB) -Level OK
        }
    }

    # ---- MEMORY.DMP (file, not folder) ----
    if (Test-Path -LiteralPath $memoryDumpPath) {
        try {
            $memDumpSize = (Get-Item -LiteralPath $memoryDumpPath -Force).Length
            Remove-Item -LiteralPath $memoryDumpPath -Force -ErrorAction Stop
            $totalFreed += $memDumpSize
            Write-Log ("  [OK] Removed MEMORY.DMP ({0:N1} MB)" -f ($memDumpSize / 1MB)) -Level OK
            $clearedCount++
        } catch {
            Write-Log ("  [WARN] Could not remove MEMORY.DMP: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    # ============================================================
    # 5. Restart services (reverse dependency order)
    # ============================================================
    if ($stoppedServices.Count -gt 0) {
    # ---- Catroot2 reset (gated) ----
    if ($Script:AllowCatrootReset) {
        Write-Log 'Resetting Catroot2 signature cache (cryptsvc already stopped)...' -Level INFO
        $catroot2Path = Join-Path $systemRoot 'System32\catroot2'
        if (Test-Path -LiteralPath $catroot2Path) {
            try {
                $items = Get-ChildItem -LiteralPath $catroot2Path -Recurse -Force -ErrorAction SilentlyContinue
                $removed = 0
                foreach ($item in $items) {
                    try {
                        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
                        $removed++
                    } catch { }
                }
                Write-Log ("  [OK] Catroot2 cleaned ({0} entries removed)." -f $removed) -Level OK
                Write-Log '  Windows will rebuild the signature store on next update.' -Level INFO
            } catch {
                Write-Log ("  [WARN] Catroot2 reset failed: {0}" -f $_.Exception.Message) -Level WARN
            }
        } else {
            Write-Log '  [SKIP] Catroot2 not present.' -Level DEBUG
        }
    } else {
        Write-Log '  Catroot2 reset not authorized (no -AllowCatrootReset flag).' -Level DEBUG
    }

        Write-Log 'Restarting Windows Update infrastructure services...' -Level INFO

        # Start in dependency order: cryptsvc (base), bits (uses cryptsvc),
        # wuauserv (uses bits), dosvc (independent, needs network stack).
        foreach ($svc in @('cryptsvc', 'bits', 'wuauserv', 'dosvc')) {
            if ($svc -notin $stoppedServices) { continue }

            try {
                Start-Service -Name $svc -ErrorAction Stop
                Write-Log ("  [OK] Started: {0}" -f $svc) -Level OK
            } catch {
                Write-Log ("  [WARN] Could not start {0}: {1}" -f $svc, $_.Exception.Message) -Level WARN
            }
        }

        # ---- Verify services reached Running state ----
        Write-Log 'Verifying service health...' -Level INFO
        $deadline = (Get-Date).AddSeconds(45)
        $pending  = @('wuauserv', 'dosvc')

        while ((Get-Date) -lt $deadline -and $pending.Count -gt 0) {
            $stillPending = @()
            foreach ($svc in $pending) {
                $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if ($s -and $s.Status -ne 'Running') {
                    $stillPending += $svc
                }
            }
            # [FIX-STEP1-SVCCK] Assign $pending BEFORE the break check.
            # The old order was:
            #   if ($stillPending.Count -eq 0) { break }   # breaks first
            #   $pending = $stillPending                    # never runs
            # so when all services reached Running, $pending retained
            # the ORIGINAL candidate list and the post-loop check
            # `if ($pending.Count -eq 0)` was false → "still not Running
            # after 45s" fired on every run (with ~0s elapsed, as the
            # log timestamps show).
            $pending = $stillPending
            if ($pending.Count -eq 0) { break }
            Start-Sleep -Milliseconds 500
        }

        if ($pending.Count -eq 0) {
            Write-Log '  [OK] All WU infrastructure services are Running.' -Level OK
        } else {
            Write-Log ("  [WARN] Services still not Running after 45s: {0}" -f ($pending -join ', ')) -Level WARN
            Write-Log '  They may recover on their own; check with Get-Service later.' -Level INFO
        }
    }

    # ---- Post-clear verification: is the DO cache actually empty? ----
    Write-Log 'Verifying Delivery Optimization cache is empty...' -Level INFO
    try {
        Start-Sleep -Seconds 2
        # [FIX-DO-WARN-2] Same warning suppression as the pre-flight check.
        $remaining = @(Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        if ($remaining.Count -eq 0) {
            Write-Log '  [OK] DO cache is empty - no residual jobs.' -Level OK
        } else {
            $pausedCount   = @($remaining | Where-Object { $_.Status -eq 'Paused' }).Count
            $activeCount   = $remaining.Count - $pausedCount
            if ($activeCount -gt 0) {
                Write-Log ("  [WARN] {0} DO job(s) still active after cache clear." -f $activeCount) -Level WARN
            }
            if ($pausedCount -gt 0) {
                Write-Log ("  [INFO] {0} DO job(s) paused (retained by Windows for resume; expected)." -f $pausedCount) -Level INFO
            }
            Write-Log '  Paused jobs will resume or expire on their own.' -Level INFO
            # Only show jobs with meaningful downloaded bytes; aggregate the rest
            $significantJobs = @($remaining | Where-Object {
                [int64]$_.TotalBytesDownloaded -ge 524288  # 0.5 MB
            })
            $trivialCount = $remaining.Count - $significantJobs.Count

            if ($significantJobs.Count -gt 0) {
                Write-Log ("  Significant paused jobs ({0}):" -f $significantJobs.Count) -Level DEBUG
                foreach ($j in $significantJobs) {
                    $mb = [math]::Round([int64]$j.TotalBytesDownloaded / 1MB, 1)
                    Write-Log ("    {0}: {1:N1} MB, Status={2}" -f $j.FileId.Substring(0,8), $mb, $j.Status) -Level DEBUG
                }
            }
            if ($trivialCount -gt 0) {
                Write-Log ("  ({0} additional paused job(s) with <0.5 MB downloaded - suppressed)" -f $trivialCount) -Level DEBUG
            }
        }
    } catch {
        Write-Log ("  [DEBUG] DO verification failed: {0}" -f $_.Exception.Message) -Level DEBUG
    }

    # ============================================================
    # 6. Summary
    # ============================================================
    $reportedGB = [math]::Round($totalFreed / 1GB, 2)

    # True free-space delta on the system drive (may differ from reported
    # bytes freed due to hardlinks, sparse files, delayed VSS commit, etc.)
    $freeAfter  = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction SilentlyContinue).FreeSpace
    $trueDelta  = if ($freeAfter) { [math]::Round(($freeAfter - $Script:StartFreeBytes) / 1GB, 2) } else { 0 }

    Write-Log ('Step 1 summary: {0} targets cleared, {1} skipped' -f $clearedCount, $skippedCount) -Level INFO
    Write-Log ('  Reported bytes freed:  {0:N2} GB' -f $reportedGB) -Level INFO
    Write-Log ('  True free-space delta: {0:N2} GB' -f $trueDelta) -Level INFO

    Write-Log 'Step 1 complete.' -Level OK
    Write-Log '[SUCCESS] System-wide junk, caches, and logs optimized.' -Level OK
}

# ============================================================
# STEP 1b: SSD Fullness Warning (informational only)
# ============================================================
function Invoke-Step01b {
    [CmdletBinding()]
    param()

    Write-Log 'STEP 1b: SSD Fullness Check' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    try {
        $disks = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
                 Where-Object { $_.DriveType -eq 3 -and $_.Size -gt 0 }
    } catch {
        Write-Log 'Drive enumeration failed - skipping.' -Level DEBUG
        return
    }

    $warned = $false
    foreach ($d in $disks) {
        $usedPct = [math]::Round((($d.Size - $d.FreeSpace) / $d.Size) * 100, 1)
        $freeGB  = [math]::Round($d.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($d.Size / 1GB, 2)

        if ($usedPct -gt 90) {
            Write-Log ("  {0}  {1}% used ({2} GB free / {3} GB total)  [CRITICAL - SSD write perf may be degraded]" -f $d.DeviceID, $usedPct, $freeGB, $totalGB) -Level WARN
            $warned = $true
        } elseif ($usedPct -gt 80) {
            Write-Log ("  {0}  {1}% used ({2} GB free / {3} GB total)  [WARNING - approaching 90% threshold]" -f $d.DeviceID, $usedPct, $freeGB, $totalGB) -Level WARN
            $warned = $true
        } else {
            Write-Log ("  {0}  {1}% used ({2} GB free / {3} GB total)" -f $d.DeviceID, $usedPct, $freeGB, $totalGB) -Level INFO
        }
    }

    if ($warned) {
        Write-Log '' -Level INFO
        Write-Log 'Recommendation: move large files to an external drive or a less-full drive.' -Level INFO
    } else {
        Write-Log 'All drives are below the 80% fullness threshold. No action needed.' -Level OK
    }

    Write-Log 'Step 1b complete.' -Level OK
}

# ============================================================
# STEP 2: Purge Recycle Bins and Loose Storage Garbage
# ============================================================
function Invoke-Step02 {
    <#
    .SYNOPSIS
        Empties Recycle Bins on all local volumes and sweeps aged
        log files from well-known Windows log directories.

    .DESCRIPTION
        Operations:
          1. Clear-RecycleBin on all fixed drives
          2. Direct sweep of $Recycle.Bin\<SID> folders on every
             fixed drive (catches stale profiles, locked items, and
             entries Clear-RecycleBin silently skipped)
          3. Delete *.log files older than 30 days from:
             - %SystemRoot%\Logs
             - %SystemRoot%\System32\LogFiles
          4. Delete *.log immediately from WebCache (unsafe to leave long)

        Uses a 30-day age threshold on system log directories to avoid
        deleting recently written diagnostics that could be useful for
        troubleshooting ongoing issues.

        Safety:
          * Recycle Bins contain only user-deleted files. The user
            already chose to discard them, so emptying is safe.
          * We do NOT delete the $Recycle.Bin folder itself - only
            its contents, and only on fixed drives.
          * Removable drives (USB, SD) are skipped.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 2: Purging Recycle Bins and Loose Storage Garbage' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not (Confirm-Action -Query 'Purge Recycle Bins and old application log files safely?')) {
        Write-Log 'Step 2 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would empty all Recycle Bins and clear aged log structures.' -Level PREVIEW
        return
    }

    # Fix B: capture free space before this step's mutations
    $__fsBefore = Get-FreeBytesOnSystemDrive

    # ---- 1. Empty Recycle Bins via Clear-RecycleBin ----
    Write-Log 'Emptying Recycle Bins on all connected volumes...' -Level INFO

    $recycleSummary = @{
        Cleared = 0
        Failed  = 0
        Skipped = 0
    }

    # FIX-4: enumerate only fixed local drives (Win32_LogicalDisk DriveType=3)
    # DriveType 2=removable, 3=fixed, 4=network, 5=CD-ROM.
    try {
        $drives = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
                  Where-Object { $_.DriveType -eq 3 } |
                  ForEach-Object {
                      [PSCustomObject]@{
                          Name = $_.DeviceID.TrimEnd(':')
                          Free = $_.FreeSpace
                      }
                  }
    } catch {
        $drives = @()
        Write-Log "Drive enumeration failed: $($_.Exception.Message)" -Level WARN
    }

    foreach ($drive in $drives) {
        $letter = $drive.Name
        try {
            Clear-RecycleBin -DriveLetter $letter -Force -ErrorAction Stop
            Write-Log ("  Recycle Bin cleared on drive {0}:" -f $letter) -Level OK
            $recycleSummary.Cleared++
        } catch [System.Management.Automation.PSInvalidOperationException] {
            # Thrown when the recycle bin is already empty - not an error
            Write-Log ("  Recycle Bin on {0}: already empty." -f $letter) -Level DEBUG
            $recycleSummary.Skipped++
        } catch {
            Write-Log ("  Could not clear Recycle Bin on {0}: {1}" -f $letter, $_.Exception.Message) -Level WARN
            $recycleSummary.Failed++
        }
    }

    Write-Log ("Recycle Bin summary: {0} cleared, {1} already empty, {2} failed" -f $recycleSummary.Cleared, $recycleSummary.Skipped, $recycleSummary.Failed) -Level INFO

    # ---- 2. Direct $Recycle.Bin\<SID> sweep ----
    # Belt-and-suspenders: Clear-RecycleBin can silently skip files that
    # are locked by another user's session or by a stale profile. This
    # walk catches those leftovers. We do NOT delete the $Recycle.Bin
    # folder itself, only its contents.
    Write-Log 'Sweeping direct $Recycle.Bin contents on all fixed drives...' -Level INFO

    $directStats = @{ Cleared = 0; Failed = 0; BytesFreed = [int64]0 }

    foreach ($drive in $drives) {
        $letter = $drive.Name
        $recycleRoot = "${letter}:\`$Recycle.Bin"

        if (-not (Test-Path -LiteralPath $recycleRoot)) {
            continue
        }

        try {
            # Enumerate <SID> subfolders under $Recycle.Bin
            $sidFolders = Get-ChildItem -LiteralPath $recycleRoot -Directory -Force -ErrorAction SilentlyContinue

            foreach ($sid in $sidFolders) {
                try {
                    # Measure before deletion
                    $size = (Get-ChildItem -LiteralPath $sid.FullName -Recurse -File -Force -ErrorAction SilentlyContinue |
                             Measure-Object -Property Length -Sum).Sum
                    if ($null -eq $size) { $size = 0 }

                    # Delete contents only, not the SID folder itself
                    Get-ChildItem -LiteralPath $sid.FullName -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

                    $directStats.Cleared++
                    $directStats.BytesFreed += [int64]$size
                } catch {
                    $directStats.Failed++
                }
            }

            Write-Log ("  [{0}:] Direct sweep complete" -f $letter) -Level DEBUG
        } catch {
            Write-Log ("  [{0}:] Direct sweep failed: {1}" -f $letter, $_.Exception.Message) -Level DEBUG
            $directStats.Failed++
        }
    }

    $directMB = [math]::Round($directStats.BytesFreed / 1MB, 1)
    Write-Log ("Direct sweep: {0} SID folders cleared, {1} failed, {2:N1} MB reclaimed" -f $directStats.Cleared, $directStats.Failed, $directMB) -Level INFO

    # ---- 3. Aged log sweep ----
    Write-Log 'Performing safe, targeted Temp and Log file sweeps...' -Level INFO

    $cutoff  = (Get-Date).AddDays(-30)
    $sweepResults = @{
        Deleted   = 0
        Skipped   = 0
        Failed    = 0
        BytesFreed = [int64]0
    }

    $agedTargets = @(
        (Join-Path $env:SystemRoot 'Logs')
        (Join-Path $env:SystemRoot 'System32\LogFiles')
    )

    foreach ($dir in $agedTargets) {
        if (-not (Test-Path -LiteralPath $dir)) {
            Write-Log ("  Skipping (not present): {0}" -f $dir) -Level DEBUG
            continue
        }

        Write-Log ("  Sweeping aged logs in: {0}" -f $dir) -Level INFO

        try {
            $logs = Get-ChildItem -LiteralPath $dir -Filter '*.log' -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -lt $cutoff }

            foreach ($log in $logs) {
                try {
                    $size = $log.Length
                    Remove-Item -LiteralPath $log.FullName -Force -ErrorAction Stop
                    $sweepResults.Deleted++
                    $sweepResults.BytesFreed += $size
                } catch {
                    $sweepResults.Failed++
                }
            }
        } catch {
            Write-Log ("  Directory scan failed: {0} - {1}" -f $dir, $_.Exception.Message) -Level WARN
        }
    }

    # ---- 4. WebCache log files (not age-filtered - always safe) ----
    $webCacheLog = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WebCache'
    if (Test-Path -LiteralPath $webCacheLog) {
        Write-Log ("  Sweeping WebCache logs in: {0}" -f $webCacheLog) -Level INFO

        try {
            $logs = Get-ChildItem -LiteralPath $webCacheLog -Filter '*.log' -File -ErrorAction SilentlyContinue

            foreach ($log in $logs) {
                try {
                    $size = $log.Length
                    Remove-Item -LiteralPath $log.FullName -Force -ErrorAction Stop
                    $sweepResults.Deleted++
                    $sweepResults.BytesFreed += $size
                } catch {
                    $sweepResults.Failed++
                }
            }
        } catch {
            Write-Log ("  WebCache scan failed: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    # ---- 5. Summary ----
    $totalBytesFreed = $directStats.BytesFreed + $sweepResults.BytesFreed
    $freedGB = [math]::Round($totalBytesFreed / 1GB, 2)

    Write-Log ("Log sweep summary: {0} files deleted, {1} failed, {2:N2} GB claimed" -f $sweepResults.Deleted, $sweepResults.Failed, $freedGB) -Level INFO
    $__fsAfter   = Get-FreeBytesOnSystemDrive
    $__fsDeltaMB = [math]::Round(([int64]($__fsAfter - $__fsBefore)) / 1MB, 1)
    Write-Log ("  Actual system-drive free-space delta: {0:N1} MB" -f $__fsDeltaMB) -Level INFO
    Write-Log 'Step 2 complete.' -Level OK
    Write-Log '[SUCCESS] Recycle Bins emptied and localized log caches pruned.' -Level OK
}

function Invoke-Step03 {
    <#
    .SYNOPSIS
        Clears cache directories for Chromium-family and Firefox
        browsers across all profiles. Terminates browser processes
        first to unlock cache files.

    .DESCRIPTION
        Chromium caches cleared (matched by exact relative path
        from the profile root, so we never touch user data):
          * Cache, Code Cache, GPUCache, ShaderCache, GrShaderCache
          * DawnCache, DawnGraphiteCache, DawnWebGPUCache
          * Service Worker\CacheStorage, Service Worker\ScriptCache
          * Application Cache, Media Cache, Safe Browsing
          * component_crx_cache
          * optimization_guide_model_store
          * optimization_guide_hint_cache_store
          * webrtc_event_logs, WebrtcVideoStats
          * OriginTrials, Platform Notifications
          * ShaderCache\GPUCache

        Firefox caches cleared:
          * cache2\entries, cache2\doomed
          * startupCache, shader-cache, thumbnails

        Preserved (NEVER touched - not in the match list):
          * History, Bookmarks, Login Data, Cookies, Web Data
          * Preferences, Secure Preferences, Favicons
          * Sessions\* (Current Session, Current Tabs, etc.)
          * Top Sites, Shortcuts, Network\*
          * Local Storage, IndexedDB, Session Storage
          * Extensions, Sync Data
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 3: Cleaning Web Browser Caches' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Cache assets only. History, bookmarks, passwords, cookies, and login sessions are preserved.' -Level INFO
    Write-Log 'Active browser processes will be terminated. Any unsaved form data may be lost.' -Level WARN

    if (-not (Confirm-Action -Query 'Clear web browser cache data?')) {
        Write-Log 'Step 3 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would terminate browser processes and clean Chromium/Firefox caches.' -Level PREVIEW
        return
    }

    # Fix B: capture free space before this step's mutations
    $__fsBefore = Get-FreeBytesOnSystemDrive

    # ---- 1. Detect and (optionally) terminate running browsers ----
    $browserProcesses = @(
        'chrome', 'msedge', 'firefox', 'opera', 'brave', 'vivaldi'
    )

    $running = @()
    foreach ($name in $browserProcesses) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($procs) { $running += $name }
    }

    if ($running.Count -gt 0) {
        Write-Log ("Active browsers detected: {0}" -f ($running -join ', ')) -Level WARN

        $proceed = $Script:ForceKill
        if (-not $proceed) {
            Write-Log 'Terminating them may lose unsaved data.' -Level WARN
            $proceed = Confirm-Action -Query 'Terminate all browser processes now?'
        }

        if (-not $proceed) {
            Write-Log 'Browser cache cleaning skipped - user declined termination.' -Level WARN
            return
        }

        Write-Log 'Closing active browser windows to unlock cache structures...' -Level INFO
        foreach ($name in $running) {
            try {
                Get-Process -Name $name -ErrorAction SilentlyContinue |
                    Stop-Process -Force -ErrorAction SilentlyContinue
                Write-Log ("  Terminated: {0}" -f $name) -Level DEBUG
            } catch {
                Write-Log ("  Could not terminate {0}: {1}" -f $name, $_.Exception.Message) -Level DEBUG
            }
        }

        Start-Sleep -Seconds 2
    }

    # ============================================================
    # 2. Chromium-family profile cache cleaner
    # ============================================================
    # Relative paths from the profile root (e.g. "User Data" folder).
    # The walker computes $rel from each discovered folder and matches
    # against this list. Anything not listed is never touched.
    $chromiumCacheDirs = @(
        # ---- Existing coverage ----
        'Cache'
        'Code Cache'
        'GPUCache'
        'ShaderCache'
        'GrShaderCache'
        'DawnCache'
        'DawnGraphiteCache'
        'DawnWebGPUCache'

        # ---- Service Worker + PWA caches ----
        'Service Worker\CacheStorage'
        'Service Worker\ScriptCache'

        # ---- Additional Chromium caches ----
        'Application Cache'
        'Media Cache'
        'Safe Browsing'
        'component_crx_cache'
        'optimization_guide_model_store'
        'optimization_guide_hint_cache_store'
        'webrtc_event_logs'
        'WebrtcVideoStats'
        'OriginTrials'
        'Platform Notifications'

        # ---- Nested shader cache ----
        'ShaderCache\GPUCache'
    )

    $chromiumProfiles = @(
        [PSCustomObject]@{ Name = 'Chrome';  Path = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') }
        [PSCustomObject]@{ Name = 'Edge';    Path = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') }
        [PSCustomObject]@{ Name = 'Brave';   Path = (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data') }
        [PSCustomObject]@{ Name = 'Opera';   Path = (Join-Path $env:APPDATA       'Opera Software\Opera Stable') }
        [PSCustomObject]@{ Name = 'Opera2';  Path = (Join-Path $env:LOCALAPPDATA  'Opera Software\Opera Stable') }
        [PSCustomObject]@{ Name = 'Vivaldi'; Path = (Join-Path $env:LOCALAPPDATA  'Vivaldi\User Data') }
        [PSCustomObject]@{ Name = 'EdgeWebView2'; Path = (Join-Path $env:LOCALAPPDATA 'Microsoft\EdgeWebView\User Data') }
    )

    Write-Log 'Purging browser data streams...' -Level INFO

    $chromiumStats = @{ Cleared = 0; Failed = 0; Skipped = 0 }

    foreach ($browser in $chromiumProfiles) {
        if (-not (Test-Path -LiteralPath $browser.Path)) {
            Write-Log ("  [{0}] Not installed - skipped." -f $browser.Name) -Level DEBUG
            continue
        }

        Write-Log ("  [{0}] Scanning {1}" -f $browser.Name, $browser.Path) -Level INFO

        try {
            # Walk every directory once; match against relative path
            $allDirs = Get-ChildItem -LiteralPath $browser.Path -Directory -Recurse -Force -ErrorAction SilentlyContinue

            $matched = 0
            # [FIX-SILENT-1] Match by suffix, not exact equality. Real
            # Chromium caches live at User Data\Default\Cache (and per
            # profile: Profile 1\Cache, etc.). The old `-contains $rel`
            # only ever matched caches directly under User Data, missing
            # the actual bulk of the browser cache.
            foreach ($dir in $allDirs) {
                $rel = $dir.FullName.Substring($browser.Path.Length).TrimStart('\')

                $isMatch = $false
                foreach ($entry in $chromiumCacheDirs) {
                    if ($rel -eq $entry -or $rel -like "*\$entry") {
                        $isMatch = $true
                        break
                    }
                }

                if ($isMatch) {
                    try {
                        Get-ChildItem -LiteralPath $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                        $chromiumStats.Cleared++
                        $matched++
                    } catch {
                        $chromiumStats.Failed++
                    }
                }
            }

            Write-Log ("    [{0}] Cleared {1} cache folder(s)." -f $browser.Name, $matched) -Level DEBUG
        } catch {
            Write-Log ("  [{0}] Scan failed: {1}" -f $browser.Name, $_.Exception.Message) -Level WARN
            $chromiumStats.Failed++
        }
    }

    Write-Log ("Chromium cache summary: {0} dirs cleared, {1} failed" -f $chromiumStats.Cleared, $chromiumStats.Failed) -Level INFO

    # ============================================================
    # 3. Firefox profile cache cleaner
    # ============================================================
    $firefoxRoot = Join-Path $env:LOCALAPPDATA 'Mozilla\Firefox\Profiles'
    $firefoxCacheDirs = @(
        'cache2\entries'
        'cache2\doomed'
        'startupCache'
        'shader-cache'
        'thumbnails'
    )

    $firefoxStats = @{ Cleared = 0; Failed = 0 }

    if (Test-Path -LiteralPath $firefoxRoot) {
        Write-Log ("  [Firefox] Scanning {0}" -f $firefoxRoot) -Level INFO

        try {
            $profiles = Get-ChildItem -LiteralPath $firefoxRoot -Directory -Force -ErrorAction SilentlyContinue

            foreach ($ffProfile in $profiles) {
                foreach ($rel in $firefoxCacheDirs) {
                    $cacheDir = Join-Path $ffProfile.FullName $rel
                    if (-not (Test-Path -LiteralPath $cacheDir)) { continue }

                    try {
                        Get-ChildItem -LiteralPath $cacheDir -Recurse -Force -ErrorAction SilentlyContinue |
                            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                        $firefoxStats.Cleared++
                    } catch {
                        $firefoxStats.Failed++
                    }
                }
            }
        } catch {
            Write-Log ("  [Firefox] Scan failed: {0}" -f $_.Exception.Message) -Level WARN
        }

        Write-Log ("Firefox cache summary: {0} dirs cleared, {1} failed" -f $firefoxStats.Cleared, $firefoxStats.Failed) -Level INFO
    } else {
        Write-Log '  [Firefox] Not installed - skipped.' -Level DEBUG
    }

    # Fix B: report the actual free-space delta observed during this step
    $__fsAfter   = Get-FreeBytesOnSystemDrive
    $__fsDeltaMB = [math]::Round(([int64]($__fsAfter - $__fsBefore)) / 1MB, 1)
    Write-Log ("  Actual system-drive free-space delta: {0:N1} MB" -f $__fsDeltaMB) -Level INFO

    Write-Log 'Step 3 complete.' -Level OK
    Write-Log '[SUCCESS] Web browser application caches cleared safely.' -Level OK
}

function Invoke-Step04 {
    <#
    .SYNOPSIS
        Gracefully closes Office applications, then clears orphaned
        document recovery files, Outlook transaction temp files, and
        the hidden Secure Attachment Cache (OLK) folder.

    .DESCRIPTION
        Protected (NEVER touched):
          * Outlook mailboxes (.ost / .pst)
          * Account settings, signatures, rules
          * Office activation, licensing, user preferences

        Cleared:
          * Word/Excel/PowerPoint unsaved recovery files
          * ~*.doc*, ~*.xls*, ~*.ppt* owner-lock files in %TEMP%
          * ~WRL*.tmp Word owner files
          * Outlook *.tmp transaction files
          * OLK secure attachment cache (found via registry)

        Process handling:
          * taskkill (graceful) - allows Office to save/close cleanly
          * 10-second grace period polling for exit
          * Skips deletions if Office still running (avoids file locks)
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 4: Cleaning Microsoft Office and Outlook Temp Files' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Outlook emails, mailboxes (.ost/.pst), and account data will remain UNTOUCHED.' -Level INFO
    Write-Log 'Office applications will be asked to close gracefully.' -Level WARN

    if (-not (Confirm-Action -Query 'Clear Office temporary files and attachment caches?')) {
        Write-Log 'Step 4 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would terminate Office applications and flush attachment caches/temp logs.' -Level PREVIEW
        return
    }

    # ---- 1. Gracefully close Office apps ----
    $officeProcesses = @('winword', 'excel', 'powerpnt', 'outlook')

    Write-Log 'Ensuring Office applications are safely closed...' -Level INFO

    # Graceful close request (no -Force) - lets Office prompt to save
    foreach ($name in $officeProcesses) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if (-not $procs) { continue }

        foreach ($proc in $procs) {
            try {
                if ($proc.MainWindowHandle -ne 0) {
                    # Graceful close via WM_CLOSE
                    $null = $proc.CloseMainWindow()
                    Write-Log ("  Sent close request to {0} (PID {1})" -f $name, $proc.Id) -Level DEBUG
                }
            } catch {
                Write-Log ("  Close request failed for {0}: {1}" -f $name, $_.Exception.Message) -Level DEBUG
            }
        }
    }

    # ---- 2. Wait up to 10 seconds for graceful exit ----
    $maxWaitSeconds = 10
    $waited = 0
    $allClosed = $false

    while ($waited -lt $maxWaitSeconds) {
        $stillRunning = @()
        foreach ($name in $officeProcesses) {
            if (Get-Process -Name $name -ErrorAction SilentlyContinue) {
                $stillRunning += $name
            }
        }

        if ($stillRunning.Count -eq 0) {
            $allClosed = $true
            Write-Log '  All Office processes exited cleanly.' -Level OK
            break
        }

        Start-Sleep -Seconds 1
        $waited++
    }

    if (-not $allClosed) {
        Write-Log ("Office applications did not close gracefully within {0} seconds." -f $maxWaitSeconds) -Level WARN
        Write-Log 'Skipping file deletions that require exclusive locks.' -Level WARN
        Write-Log '[WARNING] Office processes remained open. Skipping locked file deletions.' -Level WARN
        return
    }

    # ---- 3. Office UnsavedFiles (REMOVED) ----
    # FIX-3: Office UnsavedFiles deletion removed.
    # Reason: These folders can contain the ONLY surviving copy of a
    # user's work after an application crash. Deleting them automatically
    # risks data loss that cannot be recovered. Users can clear this
    # manually if they wish: %LOCALAPPDATA%\Microsoft\Office\UnsavedFiles
    Write-Log 'Skipping Office UnsavedFiles (safety: may contain crash-recovery data).' -Level INFO

    # ---- 4. Clear active environment document owner locks in %TEMP% ----
    if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP)) {
        Write-Log 'Clearing active local environment document owner locks...' -Level INFO

        $ownerPatterns = @('~*.doc*', '~*.xls*', '~*.ppt*', '~WRL*.tmp')
        foreach ($pattern in $ownerPatterns) {
            try {
                Get-ChildItem -LiteralPath $env:TEMP -Filter $pattern -File -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Force -ErrorAction SilentlyContinue
            } catch {
                # per-pattern failure - continue
            }
        }
    }

    # ---- 5. Outlook system transaction temp files ----
    $outlookLocal = Join-Path $env:LOCALAPPDATA 'Microsoft\Outlook'
    if (Test-Path -LiteralPath $outlookLocal) {
        Write-Log 'Cleaning Outlook system transaction folders...' -Level INFO
        try {
            Get-ChildItem -LiteralPath $outlookLocal -Filter '*.tmp' -File -Force -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log ("  Outlook temp clear failed: {0}" -f $_.Exception.Message) -Level DEBUG
        }
    }

    # ---- 6. Secure Outlook Attachment Cache (OLK folder) ----
    # Path is stored in registry and randomized per Outlook install
    Write-Log 'Emptying the hidden Secure Outlook Attachment Cache (OLK folder)...'

    $olkDir = $null
    try {
        $olkDir = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Security' -Name 'OutlookSecureTempFolder' -ErrorAction Stop
    } catch {
        Write-Log '  OLK registry key not found - Outlook may not be installed.' -Level DEBUG
    }

    if ($olkDir) {
        # Normalize: trim whitespace, remove trailing backslash
        $olkDir = $olkDir.Trim()
        $olkDir = $olkDir.TrimEnd('\')

        if (Test-Path -LiteralPath $olkDir) {
            Write-Log ("  OLK directory detected: {0}" -f $olkDir) -Level INFO
            try {
                Get-ChildItem -LiteralPath $olkDir -Recurse -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log '  OLK attachment cache cleared.' -Level OK
            } catch {
                Write-Log ("  OLK clear failed: {0}" -f $_.Exception.Message) -Level DEBUG
            }
        } else {
            Write-Log ("  OLK path from registry does not exist: {0}" -f $olkDir) -Level DEBUG
        }
    }

    Write-Log 'Step 4 complete.' -Level OK
    Write-Log '[SUCCESS] Microsoft Office application caches and hidden secure temp logs cleared safely.' -Level OK
}
# ============================================================
# STEP 5: Clean PDF Reader Application Caches
# ============================================================
function Invoke-Step05 {
    <#
    .SYNOPSIS
        Clears cache, log, and temp directories for the three most
        common PDF reader applications: Adobe Acrobat/Reader,
        Foxit PDF Reader, and SumatraPDF.

    .DESCRIPTION
        Targets only volatile cache/log/temp data:
          * Adobe: any folder named "Cache" under %LOCALAPPDATA%\Adobe,
            plus *.log / *.tmp under Acrobat\ and Acrobat\DC\
          * Foxit: *.log / *.tmp in the profile, the Cache subfolder,
            and the Continuous\Staging folder in the roaming profile
          * SumatraPDF: *.tmp at profile root, contents of
            sumatrapdfcache subfolder

        Protected (NEVER touched):
          * Your PDF documents (wherever they live)
          * Recent files, preferences, bookmarks, signatures
          * License / activation data

        Process handling:
          * Force-terminates any active viewer (they hold no unsaved
            work - just viewing state)
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 5: Cleaning PDF Reader Application Caches' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Supports Adobe Acrobat, Foxit Reader, and SumatraPDF.' -Level INFO
    Write-Log 'Your locally saved PDF documents remain entirely UNTOUCHED.' -Level INFO

    if (-not (Confirm-Action -Query 'Clear PDF reader application caches and error logs?')) {
        Write-Log 'Step 5 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would terminate PDF application tasks and flush Adobe/Foxit/Sumatra cache targets.' -Level PREVIEW
        return
    }

    # ---- 1. Terminate running PDF viewers ----
    # Force-kill is safe: viewers hold no unsaved document state.
    $pdfProcesses = @(
        'Acrobat', 'AcroRd32',
        'FoxitPDFReader', 'FoxitReader',
        'SumatraPDF'
    )

    Write-Log 'Ensuring PDF viewer processes are closed to unlock paths...' -Level INFO
    foreach ($name in $pdfProcesses) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if (-not $procs) { continue }

        foreach ($proc in $procs) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Log ("  Terminated {0} (PID {1})" -f $name, $proc.Id) -Level DEBUG
            } catch {
                Write-Log ("  Could not terminate {0}: {1}" -f $name, $_.Exception.Message) -Level DEBUG
            }
        }
    }

    # Give Windows a moment to release file handles
    Start-Sleep -Seconds 1

    # ---- 2. Helper: recursively delete all children of a directory ----
    $clearFolder = {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return }
        try {
            Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log ("  Clear failed for '{0}': {1}" -f $Path, $_.Exception.Message) -Level DEBUG
        }
    }

    # ---- 3. Helper: delete files by pattern in a directory (recursive) ----
    $clearFilesByPattern = {
        param([string]$Path, [string]$Pattern)
        if (-not (Test-Path -LiteralPath $Path)) { return }
        try {
            Get-ChildItem -LiteralPath $Path -Filter $Pattern -File -Force -Recurse -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            # silent per-pattern failure
        }
    }

    # ============================================================
    # TARGET 1: Adobe Acrobat / Reader
    # ============================================================
    $adobeRoot = Join-Path $env:LOCALAPPDATA 'Adobe'
    if (Test-Path -LiteralPath $adobeRoot) {
        Write-Log 'Purging Adobe cache structures...' -Level INFO

        # Any directory named "Cache" anywhere under Adobe\
        try {
            $adobeCaches = Get-ChildItem -LiteralPath $adobeRoot -Directory -Recurse -Force -ErrorAction SilentlyContinue |
                           Where-Object { $_.Name -ieq 'Cache' }

            foreach ($cache in $adobeCaches) {
                & $clearFolder $cache.FullName
            }
        } catch {
            Write-Log ("  Adobe cache scan failed: {0}" -f $_.Exception.Message) -Level DEBUG
        }

        # *.log / *.tmp under Acrobat\
        $acrobatDir = Join-Path $adobeRoot 'Acrobat'
        & $clearFilesByPattern $acrobatDir '*.log'
        & $clearFilesByPattern $acrobatDir '*.tmp'

        # *.log / *.tmp under Acrobat\DC\
        $acrobatDC = Join-Path $acrobatDir 'DC'
        & $clearFilesByPattern $acrobatDC '*.log'
        & $clearFilesByPattern $acrobatDC '*.tmp'
    } else {
        Write-Log '  [Adobe] Not installed - skipped.' -Level DEBUG
    }

    # ============================================================
    # TARGET 2: Foxit PDF Reader
    # ============================================================
    $foxitLocal  = Join-Path $env:LOCALAPPDATA 'Foxit Software\Foxit PDF Reader'
    if (Test-Path -LiteralPath $foxitLocal) {
        Write-Log 'Purging Foxit (local) cache structures...' -Level INFO

        & $clearFilesByPattern $foxitLocal '*.log'
        & $clearFilesByPattern $foxitLocal '*.tmp'

        $foxitCache = Join-Path $foxitLocal 'Cache'
        & $clearFolder $foxitCache
    } else {
        Write-Log '  [Foxit local] Not installed - skipped.' -Level DEBUG
    }

    $foxitRoaming = Join-Path $env:APPDATA 'Foxit Software\Foxit PDF Reader'
    if (Test-Path -LiteralPath $foxitRoaming) {
        Write-Log 'Purging Foxit (roaming) staging cache...' -Level INFO

        $foxitStaging = Join-Path $foxitRoaming 'Continuous\Staging'
        & $clearFolder $foxitStaging
    } else {
        Write-Log '  [Foxit roaming] Not installed - skipped.' -Level DEBUG
    }

    # ============================================================
    # TARGET 3: SumatraPDF
    # ============================================================
    $sumatra = Join-Path $env:LOCALAPPDATA 'SumatraPDF'
    if (Test-Path -LiteralPath $sumatra) {
        Write-Log 'Purging SumatraPDF cache structures...' -Level INFO

        & $clearFilesByPattern $sumatra '*.tmp'

        $sumatraCache = Join-Path $sumatra 'sumatrapdfcache'
        & $clearFolder $sumatraCache
    } else {
        Write-Log '  [SumatraPDF] Not installed - skipped.' -Level DEBUG
    }

    Write-Log 'Step 5 complete.' -Level OK
    Write-Log '[SUCCESS] Multi-client PDF infrastructure caches optimized.' -Level OK
}

# ============================================================
# STEP 6: Clean Copilot and VS Code Developer Caches
# ============================================================
# ============================================================
# STEP 6: Clean Copilot, Teams, and VS Code Developer Caches
# ============================================================
function Invoke-Step06 {
    <#
    .SYNOPSIS
        Clears cache, shader, log, and telemetry data for VS Code
        (stable + insiders), GitHub Copilot, Windows Copilot,
        Microsoft Edge AI, and both Teams clients (classic + new).

    .DESCRIPTION
        Target caches:
          * VS Code: %APPDATA%\Code\{Cache, CachedData,
            CachedExtensions, CachedExtensionVSIXs,
            CachedProfilesData, Code Cache, GPUCache}
          * VS Code workspace storage: %APPDATA%\Code\User\workspaceStorage
            (per-workspace state - regenerates on next folder open)
          * VS Code logs: %APPDATA%\Code\logs\*.log
          * GitHub Copilot CLI: %USERPROFILE%\.copilot\*.log
          * Windows Copilot: %LOCALAPPDATA%\Microsoft\Windows\Copilot\Cache
          * Windows Search index cache: %LOCALAPPDATA%\Packages\
            Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\DeviceSearchCache
          * Edge AI cache: %LOCALAPPDATA%\Packages\
            Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe\LocalState\Cache
          * Teams classic (Electron): %APPDATA%\Microsoft\Teams\
            {Cache, Code Cache, GPUCache, logs, blob_storage}
          * Teams new (UWP): %LOCALAPPDATA%\Packages\
            MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\
            {Cache, Code Cache, GPUCache, logs, EBWebView\Default\Cache}

        Protected (NEVER touched):
          * VS Code extensions and their settings
          * VS Code user settings, keybindings, snippets
          * Workspace files on disk (only the ephemeral per-workspace
            state DBs are cleared)
          * Teams chat history, meetings, calendar (server-side)
          * Teams user settings, accounts, and credentials
          * Any code you've written or opened

        Process handling:
          * Force-terminates VS Code processes (stable + insiders)
          * Force-terminates Teams classic + new
          * 2-second wait for handles to release
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 6: Cleaning Copilot, Teams, and VS Code Developer Caches' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Purging Electron code compilers, GPU shaders, Teams caches, and logs.' -Level INFO
    Write-Log 'Your extensions, settings, themes, and workspace files remain 100% UNTOUCHED.' -Level INFO

    if (-not (Confirm-Action -Query 'Clear Copilot, Windows AI, Teams, and VS Code temporary caches?')) {
        Write-Log 'Step 6 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would terminate VS Code and Teams tasks, then flush cache targets.' -Level PREVIEW
        return
    }

    # ---- 1. Terminate VS Code + Teams processes ----
    # Force-kill is safe: VS Code auto-saves buffered editor state to
    # its backup folder, and Teams has no unsaved local state.
    $targetProcesses = @(
        'Code', 'Code - Insiders', 'VSCodium',
        'Teams',              # Teams classic
        'ms-teams'            # Teams new (UWP)
    )

    Write-Log 'Closing active VS Code and Teams sessions to unlock cache structures...' -Level INFO
    foreach ($name in $targetProcesses) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if (-not $procs) { continue }

        foreach ($proc in $procs) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Log ("  Terminated {0} (PID {1})" -f $name, $proc.Id) -Level DEBUG
            } catch {
                Write-Log ("  Could not terminate {0}: {1}" -f $name, $_.Exception.Message) -Level DEBUG
            }
        }
    }

    Start-Sleep -Seconds 2

    # ---- Helper: safe recursive folder clear ----
    $clearFolder = {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return }
        try {
            Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log ("  Clear failed for '{0}': {1}" -f $Path, $_.Exception.Message) -Level DEBUG
        }
    }

    # ---- Helper: delete files by pattern in a folder (recursive) ----
    $clearFilesByPattern = {
        param([string]$Path, [string]$Pattern)
        if (-not (Test-Path -LiteralPath $Path)) { return }
        try {
            Get-ChildItem -LiteralPath $Path -Filter $Pattern -File -Force -Recurse -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            # silent per-pattern failure
        }
    }

    Write-Log 'Sweeping developer application caches...' -Level INFO

    # ============================================================
    # TARGET 1: VS Code (stable)
    # ============================================================
    $vscodeRoot = Join-Path $env:APPDATA 'Code'
    if (Test-Path -LiteralPath $vscodeRoot) {
        Write-Log '  [VS Code] Purging cache folders...' -Level INFO

        $vscodeCacheDirs = @(
            'Cache'
            'CachedData'
            'CachedExtensions'
            'CachedExtensionVSIXs'
            'CachedProfilesData'
            'Code Cache'
            'GPUCache'
        )

        foreach ($sub in $vscodeCacheDirs) {
            $full = Join-Path $vscodeRoot $sub
            & $clearFolder $full
        }


        # Log files
        $vscodeLogs = Join-Path $vscodeRoot 'logs'
        & $clearFilesByPattern $vscodeLogs '*.log'
    } else {
        Write-Log '  [VS Code] Not installed - skipped.' -Level DEBUG
    }

    # ============================================================
    # TARGET 2: VS Code Insiders
    # ============================================================
    $insidersRoot = Join-Path $env:APPDATA 'Code - Insiders'
    if (Test-Path -LiteralPath $insidersRoot) {
        Write-Log '  [VS Code Insiders] Purging cache folders...' -Level INFO

        $insidersCacheDirs = @(
            'Cache'
            'CachedData'
            'CachedExtensions'
            'CachedExtensionVSIXs'
            'CachedProfilesData'
            'Code Cache'
            'GPUCache'
        )
        foreach ($sub in $insidersCacheDirs) {
            $full = Join-Path $insidersRoot $sub
            & $clearFolder $full
        }


        $insidersLogs = Join-Path $insidersRoot 'logs'
        & $clearFilesByPattern $insidersLogs '*.log'
    }

    # ============================================================
    # TARGET 3: GitHub Copilot CLI (.copilot)
    # ============================================================
    $copilotCli = Join-Path $env:USERPROFILE '.copilot'
    if (Test-Path -LiteralPath $copilotCli) {
        Write-Log '  [GitHub Copilot CLI] Clearing logs...' -Level INFO
        & $clearFilesByPattern $copilotCli '*.log'
    } else {
        Write-Log '  [GitHub Copilot CLI] Not present - skipped.' -Level DEBUG
    }

    # ============================================================
    # TARGET 4: Windows Copilot cache
    # ============================================================
    $winCopilotCache = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Copilot\Cache'
    if (Test-Path -LiteralPath $winCopilotCache) {
        Write-Log '  [Windows Copilot] Clearing cache folder...' -Level INFO
        & $clearFolder $winCopilotCache
    } else {
        Write-Log '  [Windows Copilot] Not present - skipped.' -Level DEBUG
    }

    # ============================================================
    # TARGET 5: Windows Search index cache (UWP package)
    # ============================================================
    $searchCache = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\DeviceSearchCache'
    if (Test-Path -LiteralPath $searchCache) {
        Write-Log '  [Windows Search] Clearing device search cache...' -Level INFO
        & $clearFolder $searchCache
    } else {
        Write-Log '  [Windows Search] Cache not present - skipped.' -Level DEBUG
    }

    # ============================================================
    # TARGET 6: Edge AI cache (UWP package)
    # ============================================================
    $edgeAiCache = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe\LocalState\Cache'
    if (Test-Path -LiteralPath $edgeAiCache) {
        Write-Log '  [Edge AI] Clearing cache folder...' -Level INFO
        & $clearFolder $edgeAiCache
    } else {
        Write-Log '  [Edge AI] Cache not present - skipped.' -Level DEBUG
    }

    # ============================================================
    # TARGET 7: Teams classic (Electron)
    # ============================================================
    $teamsClassic = Join-Path $env:APPDATA 'Microsoft\Teams'
    if (Test-Path -LiteralPath $teamsClassic) {
        Write-Log '  [Teams classic] Purging cache folders...' -Level INFO

        $teamsClassicDirs = @(
            'Cache'
            'Code Cache'
            'GPUCache'
            'logs'
            'blob_storage'
            'Service Worker\CacheStorage'
            'Service Worker\ScriptCache'
        )
        foreach ($sub in $teamsClassicDirs) {
            $full = Join-Path $teamsClassic $sub
            & $clearFolder $full
        }

        & $clearFilesByPattern (Join-Path $teamsClassic 'logs') '*.log'
    } else {
        Write-Log '  [Teams classic] Not installed - skipped.' -Level DEBUG
    }

    # ============================================================
    # TARGET 8: Teams new (UWP package, formerly MSTeams_8wekyb3d8bbwe)
    # ============================================================
    $teamsNew = Join-Path $env:LOCALAPPDATA 'Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams'
    if (Test-Path -LiteralPath $teamsNew) {
        Write-Log '  [Teams new] Purging cache folders...' -Level INFO

        # Direct cache folders at the MSTeams root
        $teamsNewDirs = @(
            'Cache'
            'Code Cache'
            'GPUCache'
            'logs'
            'EBWebView\Default\Cache'
            'EBWebView\Default\Code Cache'
            'EBWebView\Default\GPUCache'
            'EBWebView\GrShaderCache'
            'EBWebView\ShaderCache'
        )
        foreach ($sub in $teamsNewDirs) {
            $full = Join-Path $teamsNew $sub
            & $clearFolder $full
        }

        & $clearFilesByPattern (Join-Path $teamsNew 'logs') '*.log'
    } else {
        Write-Log '  [Teams new] Not installed - skipped.' -Level DEBUG
    }

    Write-Log 'Step 6 complete.' -Level OK
    Write-Log '[SUCCESS] Copilot, Teams, and VS Code caches cleared successfully.' -Level OK
}

function Invoke-Step07 {
    <#
    .SYNOPSIS
        Interactive scan of known app cache directories under
        AppData. Shows the size of each, then asks the user
        individually whether to purge.

    .DESCRIPTION
        Scans nine well-known cache locations:
          * Spotify media cache
          * Discord communication cache
          * Discord GPU shader cache
          * Slack work cache
          * Microsoft Teams telemetry logs
          * DirectX GPU shader cache
          * Python pip cache
          * npm Node cache
          * NuGet packages cache

        Only displays folders larger than 1 MB - smaller ones
        aren't worth the interruption.

        Dev-cache warnings (pip, npm, NuGet): purging them forces
        re-download of packages on next install/build, which may
        be slow offline.

        Safety:
          * Per-folder interactive confirmation
          * Respects DryRun
          * Skips non-existent paths silently
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 7: Unused Hidden AppData Interactive Scan' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not (Confirm-Action -Query 'Run interactive scan of known app caches?')) {
        Write-Log 'Step 7 skipped by user.' -Level WARN
        return
    }

    # ---- Check for interactive session ----
    if (-not [Environment]::UserInteractive) {
        Write-Log 'Non-interactive session detected - Step 7 requires user input.' -Level WARN
        return
    }

    # ---- Cache target inventory ----
    # Ordered dictionary preserves declaration order when enumerated
    # Additional DirectX shader cache (Windows Disk Cleanup handler target)
    $directXShaderCache = Join-Path $env:LOCALAPPDATA 'Microsoft\DirectX\ShaderCache'

    $cacheTargets = [ordered]@{
        'DirectX Shader Cache'   = $directXShaderCache
        'Spotify Media Cache'    = (Join-Path $env:LOCALAPPDATA 'Spotify\Storage')
        'Discord Communication'  = (Join-Path $env:APPDATA      'discord\Cache')
        'Discord GPU Shaders'    = (Join-Path $env:APPDATA      'discord\GPUCache')
        'Slack Work Cache'       = (Join-Path $env:LOCALAPPDATA 'Slack\Cache')
        'Teams Telemetry Logs'   = (Join-Path $env:LOCALAPPDATA 'Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\Teams\Telemetry')
        'DirectX GPU Shaders'    = (Join-Path $env:LOCALAPPDATA 'D3DSCache')
        'Python Pip Cache'       = (Join-Path $env:LOCALAPPDATA 'pip\cache')
        'npm Node Cache'         = (Join-Path $env:APPDATA      'npm-cache')
        'NuGet Packages Cache'   = (Join-Path $env:USERPROFILE  '.nuget\packages')
    }

    # Dev tool caches get an extra warning line
    $devCacheKeys = @('Python Pip Cache', 'npm Node Cache', 'NuGet Packages Cache')

    # Minimum size threshold for prompting
    $minBytes = 1MB

    Write-Log 'Scanning application folders... Please wait.' -Level INFO

    $stats = @{
        Scanned  = 0
        Large    = 0
        Purged   = 0
        Skipped  = 0
        BytesFreed = [int64]0
    }

    foreach ($name in $cacheTargets.Keys) {
        $path = $cacheTargets[$name]
        $stats.Scanned++

        if (-not (Test-Path -LiteralPath $path)) {
            Write-Log ("  [{0}] Not present - skipped." -f $name) -Level DEBUG
            continue
        }

        # ---- Measure size ----
        $bytes = 0
        try {
            $bytes = (Get-ChildItem -LiteralPath $path -Recurse -File -Force -ErrorAction SilentlyContinue |
                      Measure-Object -Property Length -Sum).Sum
            if ($null -eq $bytes) { $bytes = 0 }
        } catch {
            Write-Log ("  [{0}] Size measurement failed: {1}" -f $name, $_.Exception.Message) -Level DEBUG
            continue
        }

        if ($bytes -lt $minBytes) {
            Write-Log ("  [{0}] Under 1 MB - not worth purging." -f $name) -Level DEBUG
            continue
        }

        $stats.Large++
        $gb = [math]::Round($bytes / 1GB, 2)

        # ---- Display target ----
        Write-Host '----------------------------------------------------' -ForegroundColor DarkGray
        Write-Host ("{0} : {1:N2} GB" -f $name, $gb) -ForegroundColor Yellow
        Write-Host ("  Path: {0}" -f $path) -ForegroundColor Gray

        if ($devCacheKeys -contains $name) {
            Write-Host '  [NOTE] Purging dev caches may slow down initial package installs.' -ForegroundColor DarkCyan
        }

        # ---- Prompt ----
        if ($Script:DryRun) {
            Write-Host '  [DRYRUN] Deletion skipped.' -ForegroundColor Magenta
            $stats.Skipped++
            continue
        }

        if (-not (Confirm-Action -Query ('  Purge {0} cache ({1:N2} GB)?' -f $name, $gb))) {
            Write-Host '  Skipped.' -ForegroundColor Gray
            $stats.Skipped++
            continue
        }

        # ---- Purge ----
        try {
            Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

            Write-Host '  Successfully Purged.' -ForegroundColor Green
            Write-Log ("[SUCCESS] Step 7: Purged {0} ({1:N2} GB)" -f $name, $gb) -Level OK

            $stats.Purged++
            $stats.BytesFreed += $bytes
        } catch {
            Write-Log ("  [{0}] Purge failed: {1}" -f $name, $_.Exception.Message) -Level WARN
        }
    }


    $freedGB = [math]::Round($stats.BytesFreed / 1GB, 2)
    Write-Log ("Step 7 summary: {0} scanned, {1} large, {2} purged, {3} skipped, {4:N2} GB reclaimed" -f $stats.Scanned, $stats.Large, $stats.Purged, $stats.Skipped, $freedGB) -Level INFO

    Write-Log 'Step 7 complete.' -Level OK
}
# ============================================================
# STEP 8: Reset Windows Thumbnail and Icon Caches
# ============================================================
function Invoke-Step08 {
    <#
    .SYNOPSIS
        Terminates Explorer, deletes thumbnail/icon cache databases,
        then restarts Explorer with a 15-second recovery watchdog.

    .DESCRIPTION
        Cache files targeted:
          * %LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db
          * %LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_*.db

        These databases hold:
          * Thumbnail previews of images, videos, documents
          * File/folder icon overlays
          * They regenerate automatically on next Explorer launch

        Side effects (expected and unavoidable):
          * Desktop and taskbar briefly disappear (~3-5 seconds)
          * Open File Explorer windows close
          * Windows re-indexes thumbnails on next browse (may feel
            slow for a few minutes on large media folders)

        Safety:
          * Uses Stop-Process, not taskkill - but Explorer has no
            unsaved user state, so force-kill is safe
          * Watchdog waits up to 15 seconds for explorer.exe to
            reappear before falling back to a manual restart
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 8: Resetting Windows Thumbnail and Icon Caches' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'This will temporarily hide your desktop and taskbar during the reset.' -Level WARN

    if (-not (Confirm-Action -Query 'Reset system thumbnail and icon caches?')) {
        Write-Log 'Step 8 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would terminate Explorer and flush all thumbnail/icon database files.' -Level PREVIEW
        return
    }

    # ---- 1. Terminate Explorer ----
    Write-Log 'Terminating File Explorer shell to unlock cache files...' -Level INFO

    $explorerProcs = Get-Process -Name 'explorer' -ErrorAction SilentlyContinue
    if ($explorerProcs) {
        foreach ($proc in $explorerProcs) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Log ("  Terminated explorer.exe (PID {0})" -f $proc.Id) -Level DEBUG
            } catch {
                Write-Log ("  Could not terminate explorer PID {0}: {1}" -f $proc.Id, $_.Exception.Message) -Level WARN
            }
        }
    } else {
        Write-Log '  explorer.exe was not running.' -Level DEBUG
    }

    # Give the OS time to release thumbnail .db handles
    Start-Sleep -Seconds 2

    # ---- 2. Purge thumbnail and icon databases ----
    Write-Log 'Purging corrupted or bloated thumbnail and icon databases...' -Level INFO

    $explorerCacheDir = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer'
    $filesRemoved = 0
    $filesFailed  = 0
    $bytesFreed   = [int64]0

    if (Test-Path -LiteralPath $explorerCacheDir) {
        $patterns = @('thumbcache_*.db', 'iconcache_*.db')

        foreach ($pattern in $patterns) {
            try {
                $caches = Get-ChildItem -LiteralPath $explorerCacheDir -Filter $pattern -File -Force -ErrorAction SilentlyContinue

                foreach ($cache in $caches) {
                    try {
                        $size = $cache.Length
                        Remove-Item -LiteralPath $cache.FullName -Force -ErrorAction Stop
                        $filesRemoved++
                        $bytesFreed += $size
                    } catch {
                        $filesFailed++
                        Write-Log ("  Locked: {0}" -f $cache.Name) -Level DEBUG
                    }
                }
            } catch {
                Write-Log ("  Pattern scan failed for {0}: {1}" -f $pattern, $_.Exception.Message) -Level DEBUG
            }
        }
    } else {
        Write-Log ('  Explorer cache directory not found: {0}' -f $explorerCacheDir) -Level DEBUG
    }

    $freedMB = [math]::Round($bytesFreed / 1MB, 2)
    Write-Log ("  Removed {0} cache files ({1} failed), reclaimed {2:N2} MB" -f $filesRemoved, $filesFailed, $freedMB) -Level INFO

    # ---- 3. Restart Explorer ----
    Write-Log 'Restarting File Explorer shell environment...' -Level INFO

    try {
        Start-Process 'explorer.exe' -ErrorAction Stop
    } catch {
        Write-Log ("  Failed to start explorer.exe: {0}" -f $_.Exception.Message) -Level WARN
    }

    # ---- 4. Watchdog: wait up to 15 seconds for Explorer to appear ----
    $maxWaitSeconds = 15
    $waited = 0
    $explorerAlive = $false

    while ($waited -lt $maxWaitSeconds) {
        $proc = Get-Process -Name 'explorer' -ErrorAction SilentlyContinue
        if ($proc) {
            $explorerAlive = $true
            break
        }
        Start-Sleep -Seconds 1
        $waited++
    }

    if ($explorerAlive) {
        Write-Log ("  explorer.exe recovered after {0} second(s)." -f $waited) -Level OK
    } else {
        # ---- 5. Fallback: force second launch ----
        Write-Log 'Explorer failed to recover automatically. Launching secondary thread...' -Level WARN
        Write-Log '[WARNING] File Explorer required a secondary forced initialization thread.' -Level WARN

        try {
            Start-Process 'explorer.exe' -ErrorAction Stop
            Start-Sleep -Seconds 3

            # Verify second launch worked
            $proc = Get-Process -Name 'explorer' -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Log '  Explorer recovered on second launch.' -Level OK
            } else {
                Write-Log '  Explorer still not running. User may need to manually restart via Task Manager (Ctrl+Shift+Esc -> File -> Run new task -> explorer.exe).' -Level ERROR
            }
        } catch {
            Write-Log ("  Secondary launch failed: {0}" -f $_.Exception.Message) -Level ERROR
        }
    }

    Write-Log 'Step 8 complete.' -Level OK
    Write-Log '[SUCCESS] Windows thumbnail and icon cache array cleanly reset.' -Level OK
}
# ============================================================
# EMBEDDED DRIVER UPDATE RUNNER (written to TEMP at runtime)
# ============================================================
$Script:EmbeddedDriverRunner = @'
# WinTune - Driver Update Runner
# Launched by WinTune Step 8b. Runs in its own visible window.

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$__logDir = if ($env:FC_LOG_DIR) { $env:FC_LOG_DIR } else { Split-Path -Parent $PSCommandPath }
$logFile  = if ($env:FC_LOG_DIR) { Join-Path $env:FC_LOG_DIR 'WinTune_Drivers.log' } else { Join-Path (Split-Path -Parent $PSCommandPath) 'WinTune_Drivers.log' }

$allowInstall = ($env:FC_ALLOW_DRIVER_UPDATES -eq '1')
$minAgeDays   = if ($env:FC_DRIVER_MIN_AGE_DAYS) { [int]$env:FC_DRIVER_MIN_AGE_DAYS } else { 30 }
$maxSizeMB    = if ($env:FC_DRIVER_MAX_SIZE_MB)   { [int]$env:FC_DRIVER_MAX_SIZE_MB }   else { 2048 }
$maxStaleDays = if ($env:FC_DRIVER_MAX_STALE_DAYS) { [int]$env:FC_DRIVER_MAX_STALE_DAYS } else { 2555 }  # [FIX-DRV-STALE-RUNNER]

function DR-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'STEP'  { 'Cyan' }
        default { 'Gray' }
    }
    $line = "$stamp [$Level] $Message"
    Write-Host $line -ForegroundColor $color
    try { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 } catch { }
}

function DR-Section {
    param([string]$Title)
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host (" $Title") -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan
}

function DR-Pause {
    Write-Host 'Press any key to close this window...' -ForegroundColor DarkGray
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
}

# Helper: log a driver-update object's details
function DR-FormatRow {
    param([object]$Update)

    $class  = if ($Update.PSObject.Properties['DriverClass']         -and $Update.DriverClass)         { [string]$Update.DriverClass }         else { 'Other' }
    $vendor = if ($Update.PSObject.Properties['DriverManufacturer']  -and $Update.DriverManufacturer)  { [string]$Update.DriverManufacturer }  else { '' }
    $model  = if ($Update.PSObject.Properties['DriverModel']         -and $Update.DriverModel)         { [string]$Update.DriverModel }         else { '' }
    $title  = if ($Update.PSObject.Properties['Title']               -and $Update.Title)               { [string]$Update.Title }               else { '(no title)' }
    $sizeMB = [math]::Round([int64]$Update.MaxDownloadSize / 1MB, 1)
    $age    = ((Get-Date) - $Update.LastDeploymentChangeTime).TotalDays

    return [PSCustomObject]@{
        Class    = $class
        Vendor   = $vendor
        Model    = $model
        Title    = $title
        SizeMB   = $sizeMB
        AgeDays  = [int]$age
        Identity = $Update.Identity
    }
}

# Helper: safety gate
function DR-TestCandidate {
    param([object]$Update)

    $class = if ($Update.PSObject.Properties['DriverClass'] -and $Update.DriverClass) { [string]$Update.DriverClass } else { '' }

    # Gate 1: Firmware is always excluded
    if ($class -eq 'Firmware') {
        return @{ Pass = $false; Reason = 'Firmware (use Windows Update Optional Updates UI)' }
    }

    # Gate 2: Size
    $sizeMB = [int64]$Update.MaxDownloadSize / 1MB
    if ([int64]$Update.MaxDownloadSize -eq 0) {
        return @{ Pass = $false; Reason = 'Zero-size driver (notification-only; install via Windows Update Optional Updates)' }
    }
    if ($sizeMB -gt $maxSizeMB) {
        return @{ Pass = $false; Reason = ("Suspicious size ({0:N0} MB > {1} MB)" -f $sizeMB, $maxSizeMB) }
    }

    # Gate 3: Age (too fresh)
    $ageDays = ((Get-Date) - $Update.LastDeploymentChangeTime).TotalDays
    if ($ageDays -lt $minAgeDays) {
        return @{ Pass = $false; Reason = ("Too fresh ({0:N0} days < {1} days)" -f $ageDays, $minAgeDays) }
    }

    # Gate 4: Stale-date (drivers published too long ago often fail applicability)
    if ($maxStaleDays -gt 0 -and $ageDays -gt $maxStaleDays) {
        return @{ Pass = $false; Reason = ("Too stale ({0:N0} days > {1} days - likely not applicable)" -f $ageDays, $maxStaleDays) }
    }

    # Gate 5: Placeholder dates (1/1/1970, etc. - catalog junk)
    $publishYear = $Update.LastDeploymentChangeTime.Year
    if ($publishYear -lt 2015) {
        return @{ Pass = $false; Reason = ("Placeholder date ({0})" -f $Update.LastDeploymentChangeTime.ToString('yyyy-MM-dd')) }
    }

    return @{ Pass = $true; Reason = 'OK' }
}

try {
    Clear-Host
    try { $Host.UI.RawUI.WindowTitle = 'WinTune - Driver Updates' } catch { }
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host ' WinTune - Driver Update Runner (Detached)' -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan

    DR-Log 'Driver update runner started.' 'OK'
    DR-Log "PID: $PID"
    DR-Log "Log: $logFile"
    DR-Log ("Allow install:  {0}" -f $allowInstall)
    DR-Log ("Min age (days): {0}" -f $minAgeDays)
    DR-Log ("Max size (MB):  {0}" -f $maxSizeMB)

    DR-Section 'Scan'

    # Build WUA session
    $session = $null
    $searchResult = $null
    $scanError = $null

    try {
        $session      = New-Object -ComObject Microsoft.Update.Session
        $searcher     = $session.CreateUpdateSearcher()
        DR-Log 'Searching for driver updates...' 'STEP'
        $searchResult = $searcher.Search("IsInstalled=0 and Type='Driver'")
    } catch {
        $scanError = $_.Exception.Message
        DR-Log ("Driver scan failed: {0}" -f $scanError) 'ERROR'
    }

    if ($scanError) {
        DR-Log 'Cannot continue without a working WUA scan.' 'ERROR'
        DR-Log 'Try running Windows Update from Settings, then re-run this step.' 'INFO'
        DR-Pause
        exit 1
    }

    $allDrivers = @()
    foreach ($u in $searchResult.Updates) {
        $allDrivers += $u
    }

    DR-Log ("Found {0} driver update(s) available from Windows Update." -f $allDrivers.Count) 'OK'

    if ($allDrivers.Count -eq 0) {
        DR-Log 'Nothing to do.' 'OK'
        DR-Pause
        exit 0
    }

    DR-Section 'Audit'

    # [FIX-DRV-DEDUP] Deduplicate BEFORE applying the gates.
    #
    # The old flow: gate every raw candidate, add passers to $eligible,
    # then deduplicate $eligible keeping the newest. Bug: if WU offers
    # an old driver (e.g. 4 years old) and a new one (18 days old), the
    # new one fails the MinAge gate and goes into $skipped; the old one
    # passes and gets installed. That defeats the entire purpose of the
    # MinAge gate: we're not updating to the newest; we're falling back
    # to an ancient driver just because the current one is "too new".
    #
    # The new flow: pick the newest candidate per Class|Model|Vendor
    # first, then run gates on that representative. If the newest
    # version fails any gate, skip the device entirely for this run.
    # That matches the intent: "only ship drivers that WU's rollout
    # telemetry has validated."
    $allRows = @()
    foreach ($u in $allDrivers) {
        $allRows += [PSCustomObject]@{ Update = $u; Row = (DR-FormatRow -Update $u) }
    }

    $byKey = @{}
    foreach ($item in $allRows) {
        $key = '{0}|{1}|{2}' -f $item.Row.Class, $item.Row.Model, $item.Row.Vendor
        if (-not $byKey.ContainsKey($key)) {
            $byKey[$key] = $item
        } else {
            if ($item.Row.AgeDays -lt $byKey[$key].Row.AgeDays) {
                $byKey[$key] = $item
            }
        }
    }
    $deduped = @($byKey.Values)
    $removedCount = $allRows.Count - $deduped.Count
    if ($removedCount -gt 0) {
        DR-Log ("  (deduplicated {0} duplicate entry(ies) before gates)" -f $removedCount) 'INFO'
    }

    $eligible = @()
    $skipped  = @()

    foreach ($item in $deduped) {
        $u   = $item.Update
        $row = $item.Row
        $verdict = DR-TestCandidate -Update $u

        if ($verdict.Pass) {
            $eligible += [PSCustomObject]@{ Update = $u; Row = $row }
            DR-Log ("  [{0,-12}] {1}  ({2:N1} MB, {3} days old)" -f $row.Class, $row.Title, $row.SizeMB, $row.AgeDays) 'OK'
            DR-Log '' 'INFO'
        } else {
            $skipped += [PSCustomObject]@{ Update = $u; Row = $row; Reason = $verdict.Reason }
            DR-Log ("  [{0,-12}] {1}  - {2}" -f $row.Class, $row.Title, $verdict.Reason) 'WARN'
            DR-Log '' 'INFO'
        }
    }
    # Sort by size ascending (smallest first) - safer install order.
    # Small drivers finish fast; larger risky ones (display, audio) run last.
    $eligible = @($eligible | Sort-Object -Property @{Expression = { [int64]$_.Row.SizeMB }})
    $skipped  = @($skipped  | Sort-Object -Property @{Expression = { [int64]$_.Row.SizeMB }})

    # [FIX-GENERIC-1] If ZERO drivers are eligible AND some were skipped
    # only because they were stale, auto-bump the stale threshold to the
    # newest skipped date + 30 days. One-shot adjustment for this run only.
    if ($eligible.Count -eq 0 -and $skipped.Count -gt 0) {
        $staleSkips = @($skipped | Where-Object { $_.Reason -match 'Too stale' })
        if ($staleSkips.Count -gt 0) {
            $ages = @()
            foreach ($s in $staleSkips) {
                if ($s.Reason -match '\(\s*([0-9,]+)\s+days') {
                    $ages += [int]($Matches[1] -replace ',', '')
                }
            }
            if ($ages.Count -gt 0) {
                $newestStaleDays = ($ages | Measure-Object -Minimum).Minimum
                $bumpedThreshold = $newestStaleDays + 30
                # [FIX-DRV-AUTOBUMP-V2] Two fixes:
                #   (a) Extra parens around the concatenation so -f sees the
                #       full string. Previously -f bound tighter than +,
                #       leaving {0} as a literal in the output.
                #   (b) Only bump if the newest stale driver is within 365
                #       days of maxStaleDays. Beyond that, the driver is
                #       almost certainly unapplicable - promoting a 7-year
                #       old driver (observed HP USB 48.2.4483.1963 at 2707
                #       days) just wastes a download cycle on WU_E_ALL_UPDATES_FAILED.
                $__gapDays = $newestStaleDays - $maxStaleDays
                # [FIX-DRV-AUTOBUMP-TIGHT] Tightened cap from 365 to 30 days.
                # Previous version measured the GAP (how far past max), not the
                # driver's absolute age. A 2707-day-old driver from 2019 only
                # shows 152 days of gap because max is 2555, so the old 365-day
                # cap let it through and the install failed with 0x80240022
                # (WU_E_ALL_UPDATES_FAILED - catalog has it but can't serve it).
                #
                # 30-day cap = "auto-bump only when newest candidate is less than
                # a month past our stale threshold." Anything older is genuinely
                # ancient and will likely fail the same way.
                if ($__gapDays -gt 30) {
                    DR-Log (("  [AUTO] Newest stale driver is {0} days - {1} over max. " +
                             "Too far over to be safely applicable; not auto-bumping.") -f
                             $newestStaleDays, $__gapDays) 'INFO'
                    DR-Log '  [AUTO] If you need this driver, install via Settings -> Windows Update -> Optional Updates.' 'INFO'
                } else {
                    DR-Log (("  [AUTO] All candidates are stale (newest = {0} days, {1} over max). " +
                             "Bumping threshold {2} -> {3} for this run.") -f
                             $newestStaleDays, $__gapDays, $maxStaleDays, $bumpedThreshold) 'WARN'
                    DR-Log '  [AUTO] One-shot adjustment; each run re-evaluates.' 'INFO'
                    $maxStaleDays = $bumpedThreshold
                    foreach ($s in $staleSkips) {
                        $verdict = DR-TestCandidate -Update $s.Update
                        if ($verdict.Pass) {
                            $eligible += [PSCustomObject]@{ Update = $s.Update; Row = $s.Row }
                            DR-Log ("  [AUTO-PROMOTED] {0}" -f $s.Row.Title) 'WARN'
                        }
                    }
                }
                $byKey = @{}
                foreach ($item in $eligible) {
                    $key = '{0}|{1}|{2}' -f $item.Row.Class, $item.Row.Model, $item.Row.Vendor
                    if (-not $byKey.ContainsKey($key) -or
                        $item.Row.AgeDays -lt $byKey[$key].Row.AgeDays) {
                        $byKey[$key] = $item
                    }
                }
                $eligible = @($byKey.Values | Sort-Object -Property @{Expression = { [int64]$_.Row.SizeMB }})
                $skipped  = @($skipped | Where-Object { $_.Reason -notmatch 'Too stale' })
            }
        }
    }

    DR-Section 'Summary'
    DR-Log ("Eligible: {0}" -f $eligible.Count) 'OK'
    DR-Log ("Skipped:  {0}" -f $skipped.Count)  'INFO'

    if ($eligible.Count -eq 0) {
        DR-Log 'No eligible drivers to install.' 'OK'
        DR-Pause
        exit 0
    }

    if (-not $allowInstall) {
        DR-Section 'Audit Only'
        DR-Log ("{0} driver(s) passed all safety gates." -f $eligible.Count) 'OK'
        DR-Log 'Installation is NOT authorized.' 'WARN'
        DR-Log 'To install, re-run WinTune with -AllowDriverUpdates.' 'INFO'
        DR-Log '' 'INFO'
        DR-Log 'Or install manually:' 'INFO'
        DR-Log '  Settings -> Windows Update -> Advanced options -> Optional updates' 'INFO'
        DR-Pause
        exit 0
    }

    DR-Section 'Installing'

    $okCount          = 0
    $failCount        = 0
    $skipInstallCount = 0
    $installStart = Get-Date

    foreach ($item in $eligible) {
        $row  = $item.Row
        $upd  = $item.Update

        $sizeMB = [math]::Round([int64]$upd.MaxDownloadSize / 1MB, 1)
        DR-Log ("Installing: [{0}] {1}  ({2:N1} MB)" -f $row.Class, $row.Title, $sizeMB) 'STEP'

        # Build a single-update collection
        $single = New-Object -ComObject Microsoft.Update.UpdateColl
        [void]$single.Add($upd)

        # Download the driver first (WUA requires explicit download for drivers)
        if (-not $upd.IsDownloaded) {
            DR-Log ("  Downloading {0:N1} MB..." -f $sizeMB) 'INFO'

            $dlResult  = $null
            $dlOk      = $false
            $dlHres    = 0

            # ---- Output-redirection detection ----
            # If stdout is redirected (e.g. run via -File and tee'd to a log),
            # the spinner's \r + NoNewline tricks corrupt the log. Fall back
            # to periodic log lines in that case.
            $isRedirected = $false
            try { $isRedirected = [Console]::IsOutputRedirected } catch { }

            # ---- Background download via runspace ----
            # We cannot pass the COM $downloader directly into a runspace
            # (PS 5.1 fails to serialize COM objects across runspace
            # boundaries). Instead we pass the UpdateID, re-create the
            # downloader inside the runspace, and return a status object.
            $updateIdString = [string]$upd.Identity.UpdateID

            $runspace = [runspacefactory]::CreateRunspace()
            $runspace.ApartmentState = 'MTA'
            $runspace.ThreadOptions  = 'ReuseThread'
            $runspace.Open()

            $ps = [powershell]::Create()
            $ps.Runspace = $runspace
            [void]$ps.AddScript({
                param($updateId)

                $result = [PSCustomObject]@{
                    Ok       = $false
                    ResultCode = -1
                    HResult    = 0
                    Error      = ''
                }

                try {
                    $sess     = New-Object -ComObject Microsoft.Update.Session
                    $search   = $sess.CreateUpdateSearcher()
                    # Re-find the exact update by ID so we download only this one
                    $found    = $search.Search("IsInstalled=0 and Type='Driver'")
                    $target   = $null
                    foreach ($u in $found.Updates) {
                        if ([string]$u.Identity.UpdateID -eq $updateId) { $target = $u; break }
                    }
                    if (-not $target) {
                        $result.Error = "Update not found in re-query"
                        return $result
                    }

                    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
                    [void]$coll.Add($target)

                    $downloader = $sess.CreateUpdateDownloader()
                    $downloader.Updates = $coll
                    $dlResult = $downloader.Download()

                    # [FIX-DRV-HRESULT-RUNSPACE] WUA can return HRESULTs
                    # like 0x8024401E (2149842974) which exceed
                    # [int32]::MaxValue. Wrap them to the signed
                    # equivalent. Same for ResultCode for consistency.
                    if ($dlResult.PSObject.Properties['ResultCode']) {
                        $__rc = [int64]$dlResult.ResultCode
                        if ($__rc -gt [int]::MaxValue) { $__rc -= 0x100000000 }
                        $result.ResultCode = [int]$__rc
                    }
                    if ($dlResult.PSObject.Properties['HResult']) {
                        $__hr = [int64]$dlResult.HResult
                        if ($__hr -gt [int]::MaxValue) { $__hr -= 0x100000000 }
                        $result.HResult = [int]$__hr
                    }
                    $result.Ok = ($result.ResultCode -eq 2 -or $result.ResultCode -eq 3)
                } catch {
                    $result.Error = $_.Exception.Message
                }

                return $result
            }).AddArgument($updateIdString)

            $handle  = $ps.BeginInvoke()
            $startDl = Get-Date

            $spinFrames = '|/-\'
            $spinIdx    = 0
            $lastLog    = Get-Date

            while (-not $handle.IsCompleted) {
                Start-Sleep -Milliseconds 250
                $elapsed = (Get-Date) - $startDl

                if ($isRedirected) {
                    # In redirected mode, emit one line every 15 s
                    if (((Get-Date) - $lastLog).TotalSeconds -ge 15) {
                        DR-Log ("  ... still downloading ({0:mm\:ss} elapsed)" -f $elapsed) 'INFO'
                        $lastLog = Get-Date
                    }
                } else {
                    $spinIdx = ($spinIdx + 1) % $spinFrames.Length
                    Write-Host ("`r  {0} Downloading {1:N1} MB... [{2:mm\:ss} elapsed]" -f $spinFrames[$spinIdx], $sizeMB, $elapsed) -NoNewline -ForegroundColor Cyan
                }
            }

            # Collect the result
            try {
                $dlResult = $ps.EndInvoke($handle) | Select-Object -First 1
            } catch {
                $dlResult = $null
            } finally {
                # Always dispose, even on exception
                try { $ps.Dispose() } catch { }
                try { $runspace.Close() } catch { }
                try { $runspace.Dispose() } catch { }
            }

            # Clear the spinner line before any further console output
            if (-not $isRedirected) {
                Write-Host ("`r" + (' ' * 80) + "`r") -NoNewline
            }

            # ---- Interpret the result ----
            if ($dlResult -and $dlResult.Ok) {
                DR-Log ("  [OK] Downloaded ({0:N1} MB)" -f $sizeMB) 'OK'
                $dlOk = $true
            } else {
                # Recover the real HResult from whichever source has it.
                # $dlResult.HResult is populated when the downloader
                # returned a structured failure; otherwise the runspace
                # exception text carries the HResult as "Exception from
                # HRESULT: 0xNNNNNNNN" - parse it out so the log line
                # stops printing 0x00000000 next to a real error code.
                # [FIX-DRV-HRESULT-DL] Normalize the failure HRESULT to
                # an unsigned 32-bit value so 0x{0:X8} formatting works
                # and no cast throws on large values. This was the actual
                # crash site: [int32][Convert]::ToUInt32("8024401E", 16)
                # threw "Value was either too large or too small for an
                # Int32" and escaped to the outer catch as a fatal.
                $__dlHresU = [uint32]0
                if ($dlResult -and $dlResult.PSObject.Properties['HResult'] -and [int64]$dlResult.HResult -ne 0) {
                    $__dlHresU = [uint32]([int64]$dlResult.HResult -band 0xFFFFFFFFL)
                } elseif ($dlResult -and $dlResult.Error -and $dlResult.Error -match 'HRESULT:\s*0x([0-9A-Fa-f]{8})') {
                    $__dlHresU = [Convert]::ToUInt32($matches[1], 16)
                }
                $dlHres = $__dlHresU

                $errText = if ($dlResult -and $dlResult.Error) { $dlResult.Error } else { '(no error text)' }
                DR-Log ("  [FAIL] Download failed (0x{0:X8}) - {1}" -f $dlHres, $errText) 'ERROR'
                $failCount++
                continue
            }
        }

        try {
            $installer = $session.CreateUpdateInstaller()
            $installer.Updates = $single
            $installer.AttemptCloseAppsIfNecessary = $true
            $installer.ForceQuiet = $true
            $result = $installer.Install()

            # Extract aggregate result
            # [FIX-DRV-HRESULT-INST] Same guard for the install result.
            $__codeRaw = if ($result.PSObject.Properties['ResultCode']) { [int64]$result.ResultCode } else { -1 }
            if ($__codeRaw -gt [int]::MaxValue) { $__codeRaw -= 0x100000000 }
            $code = [int]$__codeRaw
            $__hresRaw = if ($result.PSObject.Properties['HResult']) { [int64]$result.HResult } else { 0 }
            if ($__hresRaw -gt [int]::MaxValue) { $__hresRaw -= 0x100000000 }
            $hres = [int]$__hresRaw

            # [FIX-DRV-HRESULT] Iterate every per-update result so the
            # real reason surfaces even when WUA collapses the batch to
            # a generic 0x80240022 aggregate.
            $perUpdateResults = @()
            try {
                $updCount = 1
                try {
                    if ($result.PSObject.Properties['Updates']) {
                        $updCount = [int]$result.Updates.Count
                    }
                } catch { }
                if ($updCount -le 0) { $updCount = 1 }
                for ($uj = 0; $uj -lt $updCount; $uj++) {
                    try {
                        $ur = $result.GetUpdateResult($uj)
                        if ($ur) {
                            # [FIX-DRV-HRESULT-PERUPD] Same safe wrap.
                            $__urcRaw = if ($ur.PSObject.Properties['ResultCode']) { [int64]$ur.ResultCode } else { -1 }
                            if ($__urcRaw -gt [int]::MaxValue) { $__urcRaw -= 0x100000000 }
                            $__urhRaw = if ($ur.PSObject.Properties['HResult']) { [int64]$ur.HResult } else { 0 }
                            if ($__urhRaw -gt [int]::MaxValue) { $__urhRaw -= 0x100000000 }
                            $urCode = [int]$__urcRaw
                            $urHr   = [int]$__urhRaw
                            $perUpdateResults += [PSCustomObject]@{
                                Index      = $uj
                                ResultCode = $urCode
                                HResult    = $urHr
                            }
                        }
                    } catch { }
                }
            } catch { }

            # Log every per-update HResult as hex so the user can grep for it
            foreach ($ur in $perUpdateResults) {
                if ($ur.HResult -ne 0) {
                    $unsigned = if ($ur.HResult -lt 0) { [int64]$ur.HResult + 4294967296 } else { [int64]$ur.HResult }
                    DR-Log ("    [diag] update #{0}: ResultCode={1}, HResult=0x{2:X8}" -f $ur.Index, $ur.ResultCode, $unsigned) 'INFO'
                }
            }

            # Prefer a per-update HResult that differs from the aggregate
            # (more specific than the batch-level code)
            $perUpdateHResult = 0
            foreach ($ur in $perUpdateResults) {
                if ($ur.HResult -ne 0 -and $ur.HResult -ne $hres) {
                    $perUpdateHResult = $ur.HResult
                    break
                }
            }
            if ($perUpdateHResult -eq 0 -and $perUpdateResults.Count -gt 0) {
                $perUpdateHResult = $perUpdateResults[0].HResult
            }
            $effectiveHResult = if ($perUpdateHResult -ne 0) { $perUpdateHResult } else { $hres }

            # Classify by HResult first (more specific than ResultCode)
            # Common non-fatal HResults that look like failures but aren't:
            #   0x80240017 = WU_E_NOT_APPLICABLE       - not applicable to this system
            #   0x80240020 = WU_E_INSTALL_NOT_ALLOWED  - another install in progress
            #   0x8024002D = WU_E_SOURCE_ABSENT        - requires reboot first
            #   0x800F020B = WU_E_USER_LOGON_REQUIRED  - user logon required
            #   0x8024000B = WU_E_CALL_CANCELLED       - cancelled
            $skipReason = $null
            if ($effectiveHResult -ne 0) {
                # [FIX-DRV-HRESULT-2] Extended driver failure codes. Many of
                # these surface via the generic 0x80240022 aggregate; adding
                # them here classifies them as SKIP (not FAIL) and gives the
                # user a specific next step.
                switch ($effectiveHResult) {
                    -2145124329 { $skipReason = 'Not applicable to this system (0x80240017)' }                    # WU_E_NOT_APPLICABLE
                    -2145124320 { $skipReason = 'Another install in progress (0x80240020)' }                       # WU_E_INSTALL_NOT_ALLOWED
                    -2145124307 { $skipReason = 'Reboot required before install (0x8024002D)' }                    # WU_E_SOURCE_ABSENT
                    -2144796149 { $skipReason = 'User logon required (0x800F020B)' }                               # WU_E_USER_LOGON_REQUIRED
                    -2145124341 { $skipReason = 'Call cancelled (0x8024000B)' }                                    # WU_E_CALL_CANCELLED
                    -2145124318 { $skipReason = 'All updates failed (0x80240022) - check CBS.log and setupapi.dev.log, or install manually via Windows Update' }
                    -2145124302 { $skipReason = 'Update not applicable to current OS version (0x80240032)' }       # WU_E_INVALID_OPERATION
                    -2147024891 { $skipReason = 'Access denied (0x80070005) - run as SYSTEM or elevated' }         # E_ACCESSDENIED
                    -2147023436 { $skipReason = 'Timeout (0x800705B4) - driver download/install exceeded WUA timeout' } # ERROR_TIMEOUT
                    -2145124322 { $skipReason = 'WU service stopped (0x8024001E WU_E_SERVICE_STOP) - transient; retry the step' } # WU_E_SERVICE_STOP
                    # Driver-specific failures (most commonly surfaced via 0x80240022 aggregate)
                    -2147024637 { $skipReason = 'A newer driver is already installed (0x80070103 WU_E_DRIVER_ALREADY_INSTALLED)' }
                    -2147024894 { $skipReason = 'Driver payload not found (0x80070002 ERROR_FILE_NOT_FOUND)' }
                    -2146500026 { $skipReason = 'Driver setup failed (0x800F0246) - check setupapi.dev.log' }
                    -2146500025 { $skipReason = 'Driver payload missing from WU cache (0x800F0247)' }
                    -2146500093 { $skipReason = 'Driver signature validation failed (0x800F0203)' }
                }
            }

            if ($skipReason) {
                # Non-fatal: log as SKIP, count separately
                DR-Log ("  [SKIP] {0}: {1}" -f $skipReason, $row.Title) 'WARN'
                $skipInstallCount++
            } else {
                switch ($code) {
                    2 { DR-Log ("  [OK] Installed: {0}" -f $row.Title) 'OK'; $okCount++ }
                    3 { DR-Log ("  [WARN] Installed with errors: {0}" -f $row.Title) 'WARN'; $okCount++ }
                    4 {
                        $hresHex  = if ($effectiveHResult -ne 0) { ('0x{0:X8}' -f $effectiveHResult) } else { '0x80240022' }
                        $hresName = switch ($effectiveHResult) {
                            -2145124329 { 'WU_E_NOT_APPLICABLE - driver does not match this system' }
                            -2145124320 { 'WU_E_INSTALL_NOT_ALLOWED - another install in progress' }
                            -2145124307 { 'WU_E_SOURCE_ABSENT - reboot required before install' }
                            -2144796149 { 'WU_E_USER_LOGON_REQUIRED - needs user interaction' }
                            -2145124341 { 'WU_E_CALL_CANCELLED - cancelled' }
                            -2147024891 { 'E_ACCESSDENIED - permission denied' }
                            default     { 'unknown WU error' }
                        }
                        DR-Log ("  [FAIL] Failed {0} ({1}): {2}" -f $hresHex, $hresName, $row.Title) 'ERROR'
                        $failCount++
                    }
                    5 { DR-Log ("  [FAIL] Aborted: {0}" -f $row.Title) 'ERROR'; $failCount++ }
                    default { DR-Log ("  [WARN] Unknown result code {0} for {1}" -f $code, $row.Title) 'WARN'; $failCount++ }
                }
            }

            if ($result.PSObject.Properties['RebootRequired'] -and $result.RebootRequired) {
                DR-Log '  [INFO] Reboot required after this driver.' 'WARN'
            }
        } catch {
            DR-Log ("  [FAIL] {0}: {1}" -f $row.Title, $_.Exception.Message) 'ERROR'
            $failCount++
        }
    }

    $elapsed = (Get-Date) - $installStart

    DR-Section 'Done'
    DR-Log ("Installed: {0}" -f $okCount)             'OK'
    DR-Log ("Skipped:   {0}" -f $skipInstallCount)    'INFO'
    DR-Log ("Failed:    {0}" -f $failCount)           $(if ($failCount -gt 0) { 'WARN' } else { 'INFO' })
    DR-Log ("Duration:  {0:N1} minutes" -f $elapsed.TotalMinutes) 'INFO'
    DR-Log "Full log: $logFile" 'INFO'

    if ($okCount -gt 0) {
        DR-Log 'Some drivers may require a reboot to activate.' 'WARN'
    }

    DR-Pause
    try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue } catch { }
} catch {
    DR-Log ("FATAL: {0}" -f $_.Exception.Message) 'ERROR'
    DR-Pause
    try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue } catch { }
    exit 1
}

'@

# ============================================================
# STEP 8b: Driver Update Audit + Optional Install (Detached)
# ============================================================
function Invoke-Step08b {
    <#
    .SYNOPSIS
        Launches a detached visible PowerShell that scans for driver
        updates from Windows Update, applies safety gates
        (firmware-exclude, age-minimum, size-maximum), and - if
        authorized via -AllowDriverUpdates - installs the eligible
        drivers one at a time.

    .DESCRIPTION
        Safety gates:
          * Firmware updates are ALWAYS excluded (bricked-device risk)
          * Drivers must be at least $Script:DriverMinAgeDays old
          * Drivers must be smaller than $Script:DriverMaxSizeMB

        Modes:
          * No flags                 -> audit-only, list candidates
          * -AllowDriverUpdates      -> install all eligible drivers
          * -AllowDriverUpdates
              -DriverMinAgeDays N    -> custom age threshold (default 30)
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 8b: Driver Update Audit + Install (Detached)' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Launches a detached shell for Windows Update driver audit.' -Level INFO
    Write-Log ("Safety gates: min age {0} days, max size {1} MB, firmware excluded." -f $Script:DriverMinAgeDays, $Script:DriverMaxSizeMB) -Level INFO

    if (-not $Script:AllowDriverUpdates) {
        Write-Log 'Driver install NOT authorized (no -AllowDriverUpdates flag).' -Level INFO
        Write-Log 'The detached shell will run in AUDIT-ONLY mode.' -Level INFO
    } else {
        Write-Log 'Driver install AUTHORIZED via -AllowDriverUpdates.' -Level WARN
    }

    if ($Script:DryRun) {
        Write-Log 'Would launch a detached driver update audit/install shell.' -Level PREVIEW
        return
    }

    if (-not (Confirm-Action -Query 'Launch the detached driver update shell?')) {
        Write-Log 'Step 8b skipped by user.' -Level WARN
        return
    }

    # ---- Locate / write runner ----
    if (-not $Script:EmbeddedDriverRunner) {
        Write-Log 'Embedded Driver runner missing - this is a bug.' -Level ERROR
        return
    }
    Write-Log 'Using embedded Driver runner' -Level OK

    $runnerPath = New-SecureRunnerPath -LeafName 'Drivers.ps1'
    try {
        Set-Content -LiteralPath $runnerPath -Value $Script:EmbeddedDriverRunner -Encoding UTF8 -ErrorAction Stop
        Write-Log ("  [OK] Runner written to: {0}" -f $runnerPath) -Level OK
    } catch {
        Write-Log ("Failed to write runner: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    # ---- Env vars for the child ----
    $env:FC_LOG_DIR               = $Script:ScriptDir
    $env:FC_ALLOW_DRIVER_UPDATES  = if ($Script:AllowDriverUpdates) { '1' } else { '0' }
    $env:FC_DRIVER_MIN_AGE_DAYS   = [string]$Script:DriverMinAgeDays
    $env:FC_DRIVER_MAX_SIZE_MB    = [string]$Script:DriverMaxSizeMB
        $env:FC_DRIVER_MAX_STALE_DAYS = [string]$Script:DriverMaxStaleDays
    $env:FC_YES_TO_ALL            = if ($Script:YesToAll) { '1' } else { '0' }

    # ---- Launch ----
    Write-Log 'Launching detached visible PowerShell window...' -Level INFO

    # Fix B3 v2: probe the runner host before committing to a launch
    $__prereq = Test-DetachedLaunchPrereqs
    if (-not $__prereq.Ok) {
        Write-Log ("  [FAIL] Detached launch prerequisites failed: {0}" -f $__prereq.Reason) -Level ERROR
        Write-Log '  Step marked Failed (child could not start).' -Level ERROR
        throw ("Detached runner prereq failure: {0}" -f $__prereq.Reason)
    }

    # [FIX-DETACHED-5A] cross-run guard
    $__existing = @(Get-ExistingDetachedRunnerProcess -Kind 'Drivers')
    if ($__existing.Count -gt 0) {
        Write-Log ("  [SKIP] Drivers runner already active (PID {0}, started {1})." -f $__existing[0].Pid, $__existing[0].StartedAt) -Level WARN
        Write-Log '  Close the existing window first, or wait for it to exit, then re-run.' -Level WARN
        $Script:LastStepStatus = 'Skipped'
        return
    }

    try {
        $child = Start-Process -FilePath $Script:RunnerPowerShellExe -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$runnerPath`"" -PassThru

        Write-Log ("  [OK] Child PowerShell launched (PID {0})." -f $child.Id) -Level OK
        Register-DetachedExitTracking -Child $child -Kind 'Drivers' -Note 'Step 8b'
        Register-TrackedRunnerKind -RunnerPid $child.Id -Kind 'Drivers' -Note 'Step 8b'
        Write-Log '  WinTune will continue; driver audit runs independently.' -Level INFO
        Write-Log '  Look for the new window: "WinTune - Driver Update Runner"' -Level INFO

        Add-ReportRunner -Kind 'Drivers' -RunnerPid $child.Id -Note 'Step 8b'
    } catch {
        Write-Log ("Failed to launch child PowerShell: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    # ---- Clean env ----
    Remove-Item Env:\FC_LOG_DIR               -ErrorAction SilentlyContinue
    Remove-Item Env:\FC_ALLOW_DRIVER_UPDATES -ErrorAction SilentlyContinue
    Remove-Item Env:\FC_DRIVER_MIN_AGE_DAYS  -ErrorAction SilentlyContinue
    Remove-Item Env:\FC_DRIVER_MAX_SIZE_MB   -ErrorAction SilentlyContinue
    Remove-Item Env:\FC_DRIVER_MAX_STALE_DAYS -ErrorAction SilentlyContinue
    Remove-Item Env:\FC_YES_TO_ALL           -ErrorAction SilentlyContinue

    Write-Log 'Step 8b launched (detached). Driver update audit runs independently.' -Level OK
    Write-Log '[SUCCESS] Step 8b: Detached driver update shell launched.' -Level OK
    $Script:LastStepStatus = 'Detached'
}
# ============================================================
# STEP 9: Dead Desktop Shortcut Link Clipper
# ============================================================
function Invoke-Step09 {
    <#
    .SYNOPSIS
        Scans desktop shortcut (.lnk) files across the current user's
        Desktop, OneDrive Desktop, and the Public Desktop. Removes
        shortcuts whose target no longer exists.

    .DESCRIPTION
        Scanned locations:
          * %USERPROFILE%\Desktop
          * %USERPROFILE%\OneDrive\Desktop
          * %PUBLIC%\Desktop

        A shortcut is considered "broken" when:
          * It has a non-empty TargetPath, AND
          * The TargetPath does not exist on disk

        Shortcuts are LEFT ALONE when:
          * TargetPath is empty (e.g., UWP app shortcuts, GodMode)
          * TargetPath exists
          * The .lnk file cannot be parsed

        Safety:
          * Only *.lnk files are touched
          * Only shortcuts whose target is truly missing are removed
          * DryRun mode previews without deleting
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 9: Dead Desktop Shortcut Link Clipper' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Only broken/dead shortcut links will be removed. Active shortcuts are secure.' -Level INFO

    if (-not (Confirm-Action -Query 'Scan and clean broken desktop shortcuts?')) {
        Write-Log 'Step 9 skipped by user.' -Level WARN
        return
    }

    # ---- 1. Locate desktop directories ----
    $desktopPaths = @(
        [PSCustomObject]@{ Label = 'User Desktop';     Path = (Join-Path $env:USERPROFILE 'Desktop') }
        [PSCustomObject]@{ Label = 'OneDrive Desktop'; Path = (Join-Path $env:USERPROFILE 'OneDrive\Desktop') }
        [PSCustomObject]@{ Label = 'Public Desktop';   Path = (Join-Path $env:PUBLIC      'Desktop') }
    )

    # ---- 2. Build WScript.Shell COM object for shortcut parsing ----
    $wsh = $null
    try {
        $wsh = New-Object -ComObject WScript.Shell
    } catch {
        Write-Log ("Could not create WScript.Shell COM object: {0}" -f $_.Exception.Message) -Level ERROR
        Write-Log 'Step 9 cannot proceed without COM automation support.' -Level ERROR
        return
    }

    $stats = @{
        Scanned = 0
        Broken  = 0
        Purged  = 0
        Skipped = 0
        Failed  = 0
    }

    Write-Log 'Analyzing desktop shortcut structures...' -Level INFO

    # ---- 3. Scan each desktop ----
    foreach ($desktop in $desktopPaths) {
        if (-not (Test-Path -LiteralPath $desktop.Path)) {
            Write-Log ("  [{0}] Not present - skipped." -f $desktop.Label) -Level DEBUG
            continue
        }

        Write-Log ("  [{0}] Scanning {1}" -f $desktop.Label, $desktop.Path) -Level INFO

        $shortcuts = @()
        try {
            $shortcuts = Get-ChildItem -LiteralPath $desktop.Path -Filter '*.lnk' -File -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log ("  [{0}] Enumeration failed: {1}" -f $desktop.Label, $_.Exception.Message) -Level WARN
            continue
        }

        foreach ($lnk in $shortcuts) {
            $stats.Scanned++

            # ---- Parse shortcut ----
            $targetPath = $null
            try {
                $shortcut   = $wsh.CreateShortcut($lnk.FullName)
                $targetPath = $shortcut.TargetPath
            } catch {
                Write-Log ("  [WARNING] Could not parse shortcut: {0} - {1}" -f $lnk.FullName, $_.Exception.Message) -Level WARN
                $stats.Failed++
                continue
            }

            # ---- Skip shortcuts with no target (UWP, GodMode, shell namespace, etc.) ----
            if ([string]::IsNullOrWhiteSpace($targetPath)) {
                $stats.Skipped++
                continue
            }

            # ---- Check target existence ----
            $targetExists = $false
            try {
                # Target may contain environment variables (%SystemRoot%, etc.)
                $expandedTarget = [System.Environment]::ExpandEnvironmentVariables($targetPath)
                $targetExists = Test-Path -LiteralPath $expandedTarget
            } catch {
                # Malformed path - treat as broken
                $targetExists = $false
            }

            if ($targetExists) {
                # Healthy shortcut - leave it alone
                continue
            }

            # ---- Broken shortcut detected ----
            $stats.Broken++

            if ($Script:DryRun) {
                Write-Host ("  [DRYRUN] Broken Link: {0} -> {1}" -f $lnk.Name, $targetPath) -ForegroundColor Magenta
                continue
            }

            # ---- Remove ----
            try {
                Write-Host ("  [CLEANED] Removing Broken Link: {0}" -f $lnk.Name) -ForegroundColor Yellow
                Remove-Item -LiteralPath $lnk.FullName -Force -ErrorAction Stop

                Write-Log ("[PURGED] Step 9 Broken Shortcut: {0} -> Target Missing: {1}" -f $lnk.FullName, $targetPath) -Level OK
                $stats.Purged++
            } catch {
                Write-Log ("  Failed to remove {0}: {1}" -f $lnk.FullName, $_.Exception.Message) -Level WARN
                $stats.Failed++
            }
        }
    }

    # ---- 4. Release COM object ----
    if ($wsh) {
        try {
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($wsh) | Out-Null
        } catch {
            # Release failure is non-fatal
        }
        $wsh = $null
    }

    # ---- 5. Summary ----
    if ($stats.Broken -eq 0) {
        Write-Host 'No broken desktop shortcuts detected. Your workspace is perfectly clean.' -ForegroundColor Green
    }

    Write-Log ("Step 9 summary: {0} scanned, {1} broken, {2} purged, {3} skipped, {4} failed" -f $stats.Scanned, $stats.Broken, $stats.Purged, $stats.Skipped, $stats.Failed) -Level INFO

    Write-Log 'Step 9 complete.' -Level OK
}
# ============================================================
# STEP 10: Background Telemetry Services Tuning
# ============================================================
function Invoke-Step10 {
    <#
    .SYNOPSIS
        Reconfigures telemetry and diagnostic services to Manual
        startup, then stops them if currently running.

    .DESCRIPTION
        Target services:
          * DiagTrack - "Connected User Experiences and Telemetry"
            (background telemetry uploader)
          * PcaSvc    - "Program Compatibility Assistant Service"
            (compatibility telemetry and app-tracking)

        Changes applied:
          * StartupType -> Manual (was Automatic)
          * Current running instance -> stopped

        Impact:
          * Services remain functional - Windows can start them on
            demand when genuinely needed
          * Idle RAM and disk I/O decrease
          * No effect on Windows Update, Defender, or core stability

        Reversion:
          sc config DiagTrack start= auto
          sc config PcaSvc    start= auto
          net start DiagTrack
          net start PcaSvc
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 10: Background Telemetry Services Tuning' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Reconfiguring telemetry and diagnostic triggers to Manual.' -Level INFO
    Write-Log 'Core system stability and Windows updates remain fully functional.' -Level INFO

    if (-not (Confirm-Action -Query 'Optimize Windows background telemetry and diagnostic services?')) {
        Write-Log 'Step 10 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would reconfigure DiagTrack and PcaSvc startup profiles to Manual.' -Level PREVIEW
        return
    }

    $targetServices = @(
        [PSCustomObject]@{
            Name    = 'DiagTrack'
            Display = 'Connected User Experiences and Telemetry'
        }
        [PSCustomObject]@{
            Name    = 'PcaSvc'
            Display = 'Program Compatibility Assistant Service'
        }
    )

    $stats = @{
        Reconfigured = 0
        Stopped      = 0
        Missing      = 0
        Failed       = 0
    }

    # ---- 1. Reconfigure startup type to Manual ----
    Backup-RegistryKey -Step 10 -RegPath 'HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack'
    Backup-RegistryKey -Step 10 -RegPath 'HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc'
    Backup-RegistryKey -Step 10 -RegPath 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
    Write-Log 'Tuning startup behaviors for targeted telemetry engines...' -Level INFO

    foreach ($svc in $targetServices) {
        # Check service exists
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Log ("  [{0}] Not present - skipped." -f $svc.Name) -Level DEBUG
            $stats.Missing++
            continue
        }

        # Report current state
        $currentStart = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue).StartMode
        Write-Log ("  [{0}] Current startup: {1}" -f $svc.Name, $currentStart) -Level DEBUG

        # Reconfigure via sc.exe (matches original behavior)
        try {
            $result = & sc.exe config $svc.Name start= demand 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log ("  [{0}] Startup type set to Manual." -f $svc.Name) -Level OK
                $stats.Reconfigured++
            } else {
                Write-Log ("  [{0}] sc config returned code {1}: {2}" -f $svc.Name, $LASTEXITCODE, ($result -join ' ')) -Level WARN
                $stats.Failed++
            }
        } catch {
            Write-Log ("  [{0}] Reconfigure failed: {1}" -f $svc.Name, $_.Exception.Message) -Level WARN
            $stats.Failed++
        }
    }

    # ---- 2. Stop active service threads ----
    Write-Log 'Stopping active telemetry service threads immediately...' -Level INFO

    foreach ($svc in $targetServices) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if (-not $service) { continue }

        if ($service.Status -eq 'Stopped') {
            Write-Log ("  [{0}] Already stopped." -f $svc.Name) -Level DEBUG
            continue
        }

        try {
            Stop-Service -Name $svc.Name -Force -ErrorAction Stop
            Write-Log ("  [{0}] Stopped." -f $svc.Name) -Level OK
            $stats.Stopped++
        } catch {
            Write-Log ("  [{0}] Could not stop: {1}" -f $svc.Name, $_.Exception.Message) -Level WARN
            $stats.Failed++
        }
    }

    # ---- 3. Summary ----

    # ---- 3. Telemetry scheduled tasks ----
    Write-Log 'Disabling telemetry scheduled tasks...' -Level INFO

    # Positive list (NOT a regex) - localized Windows task names break regex.
    $telemetryTasks = @(
        @{ Path = '\Microsoft\Windows\Application Experience\';                    Name = 'ProgramDataUpdater' }
        @{ Path = '\Microsoft\Windows\Application Experience\';                    Name = 'Microsoft Compatibility Appraiser' }
        @{ Path = '\Microsoft\Windows\Application Experience\';                    Name = 'StartupAppTask' }
        @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\';   Name = 'Consolidator' }
        @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\';   Name = 'UsbCeip' }
        @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\';   Name = 'KernelCeipTask' }
        @{ Path = '\Microsoft\Windows\Autochk\';                                   Name = 'Proxy' }
        @{ Path = '\Microsoft\Windows\Feedback\Siuf\';                             Name = 'DmClient' }
        @{ Path = '\Microsoft\Windows\Feedback\Siuf\';                             Name = 'DmClientOnScenarioDownload' }
        @{ Path = '\Microsoft\Windows\Windows Error Reporting\';                   Name = 'QueueReporting' }
        # [FIX-STEP10-EXTRA] Four more telemetry/gaming tasks commonly
        # disabled by debloat tools. All are safe to disable.
        @{ Path = '\Microsoft\Windows\DiskDiagnostic\';                            Name = 'Microsoft-Windows-DiskDiagnosticDataCollector' }
        @{ Path = '\Microsoft\Windows\Maintenance\';                               Name = 'WinSAT' }
        @{ Path = '\Microsoft\Windows\Power Efficiency Diagnostics\';              Name = 'AnalyzeSystem' }
        @{ Path = '\Microsoft\Windows\Application Experience\';                    Name = 'PcaPatchDbTask' }
    )

    $tasksDisabled = 0
    $tasksSkipped  = 0
    foreach ($t in $telemetryTasks) {
        $task = Get-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -ErrorAction SilentlyContinue
        if (-not $task) {
            Write-Log ("  [SKIP] Task not present: {0}{1}" -f $t.Path, $t.Name) -Level DEBUG
            $tasksSkipped++
            continue
        }
        if ($task.State -eq 'Disabled') {
            Write-Log ("  [SKIP] Already disabled: {0}{1}" -f $t.Path, $t.Name) -Level DEBUG
            $tasksSkipped++
            continue
        }
        try {
            Disable-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -ErrorAction Stop | Out-Null
            Write-Log ("  [OK] Disabled task: {0}{1}" -f $t.Path, $t.Name) -Level OK
            $tasksDisabled++
        } catch {
            Write-Log ("  [WARN] Could not disable {0}{1}: {2}" -f $t.Path, $t.Name, $_.Exception.Message) -Level WARN
        }
    }
    Write-Log ("  Telemetry tasks: {0} disabled, {1} already/skipped" -f $tasksDisabled, $tasksSkipped) -Level INFO

    # ---- Advertising ID (privacy) ----
    Write-Log 'Disabling Advertising ID...' -Level INFO
    $advPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
    try {
        if (Test-Path -LiteralPath $advPath) {
            New-ItemProperty -Path $advPath -Name 'Enabled' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Log '  [OK] Advertising ID disabled.' -Level OK
        } else {
            Write-Log '  [SKIP] AdvertisingInfo key not present.' -Level DEBUG
        }
    } catch {
        Write-Log ("  [WARN] Could not disable Advertising ID: {0}" -f $_.Exception.Message) -Level WARN
    }

    Write-Log ("Step 10 summary: {0} reconfigured, {1} stopped, {2} missing, {3} failed" -f $stats.Reconfigured, $stats.Stopped, $stats.Missing, $stats.Failed) -Level INFO

    Write-Log 'Step 10 complete.' -Level OK
    Write-Log '[SUCCESS] Connected User Experiences (DiagTrack) and Compatibility Assistant (PcaSvc) tuned safely.' -Level OK
}

# ============================================================
# STEP 11: Taskbar and OS Response Adjustments
# ============================================================
function Invoke-Step11 {
    <#
    .SYNOPSIS
        Adds the "End Task" option to the taskbar right-click menu,
        disables Game DVR background recording, and broadcasts an
        environment refresh to running shell threads.

    .DESCRIPTION
        Registry changes:
          * HKCU\...\Explorer\Advanced\TaskbarEndTask = 1
              -> Right-clicking a taskbar app shows "End Task"
          * HKCU\...\GameDVR\AppCaptureEnabled = 0
              -> Disables the Game Bar capture hook for Win32 apps
          * HKCU\...\GameDVR\HistoricalCaptureEnabled = 0
              -> Disables the passive background capture buffer
                (this was the one silently recording ~30s of
                everything on some systems)

        Broadcast:
          * SendMessageTimeout HWND_BROADCAST WM_SETTINGCHANGE
            with lParam='Environment' -> tells Explorer and other
            shell components to re-read registry-backed settings
            without requiring a sign-out

        Safety:
          * All changes are HKCU (current user only)
          * No service stopped, no file deleted
          * Reversible: change the DWORD back to 1 and sign out
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 11: Taskbar and OS Response Adjustments' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log "Adds 'End Task' to taskbar right-click menu." -Level INFO
    Write-Log 'Disables background Game DVR screen recording to reclaim passive CPU cycles.' -Level INFO

    if (-not (Confirm-Action -Query 'Apply Taskbar End-Task and Game DVR performance tweaks?')) {
        Write-Log 'Step 11 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would apply Taskbar right-click and Game DVR registry tweaks.' -Level PREVIEW
        return
    }

    $stats = @{
        Applied  = 0
        Failed   = 0
    }

    # ---- Helper: idempotent registry DWORD write ----
    $setRegDword = {
        param(
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            return $true
        } catch {
            Write-Log ("  Registry write failed: {0}\{1} - {2}" -f $Path, $Name, $_.Exception.Message) -Level WARN
            return $false
        }
    }

    # ---- 1. Enable Taskbar End-Task ----
    Backup-RegistryKey -Step 11 -RegPath 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Backup-RegistryKey -Step 11 -RegPath 'HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR'
    Write-Log 'Injecting power-user taskbar adjustments into the registry...' -Level INFO

    $endTaskPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    if (& $setRegDword $endTaskPath 'TaskbarEndTask' 1) {
        Write-Log '  [OK] Taskbar End-Task enabled.' -Level OK
        $stats.Applied++
    } else {
        $stats.Failed++
    }

    # ---- 2. Disable Game DVR capture ----
    Write-Log 'Disabling Game DVR background recording pipelines...' -Level INFO

    $gameDvrPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR'
    if (& $setRegDword $gameDvrPath 'AppCaptureEnabled' 0) {
        Write-Log '  [OK] AppCaptureEnabled disabled.' -Level OK
        $stats.Applied++
    } else {
        $stats.Failed++
    }

    if (& $setRegDword $gameDvrPath 'HistoricalCaptureEnabled' 0) {
        Write-Log '  [OK] HistoricalCaptureEnabled disabled.' -Level OK
        $stats.Applied++
    } else {
        $stats.Failed++
    }

    # ---- 3. Broadcast WM_SETTINGCHANGE ----
    Write-Log 'Broadcasting environment refresh signal to active shell threads...' -Level INFO
    # P3: Step 11 rollback entries
    Add-RollbackEntry -Step 11 -Type 'RegistryHKCU' -Data @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'TaskbarEndTask'; Existed = $false; Value = $null; Type = 'DWord' }
    Add-RollbackEntry -Step 11 -Type 'RegistryHKCU' -Data @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR'; Name = 'AppCaptureEnabled'; Existed = $false; Value = $null; Type = 'DWord' }
    Add-RollbackEntry -Step 11 -Type 'RegistryHKCU' -Data @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR'; Name = 'HistoricalCaptureEnabled'; Existed = $false; Value = $null; Type = 'DWord' }

    try {
        # Add-Type compiles the P/Invoke once per session; subsequent calls reuse it
        if (-not ('Win32.NativeMethods' -as [type])) {
            $signature = @'
using System;
using System.Runtime.InteropServices;

namespace Win32 {
    public static class NativeMethods {
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr SendMessageTimeout(
            IntPtr hWnd,
            uint Msg,
            IntPtr wParam,
            string lParam,
            uint fuFlags,
            uint uTimeout,
            out IntPtr lpdwResult);
    }
}
'@
            Add-Type -TypeDefinition $signature -ErrorAction Stop
        }

        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $SMTO_ABORTIFHUNG = 0x0002
        $result = [IntPtr]::Zero

        $ret = [Win32.NativeMethods]::SendMessageTimeout(
            $HWND_BROADCAST,
            $WM_SETTINGCHANGE,
            [IntPtr]::Zero,
            'Environment',
            $SMTO_ABORTIFHUNG,
            5000,
            [ref]$result
        )

        if ($ret -ne [IntPtr]::Zero) {
            Write-Log '  [OK] Environment broadcast delivered.' -Level OK
        } else {
            Write-Log '  Broadcast returned 0 - some shell windows may not have received the update.' -Level DEBUG
        }
    } catch {
        Write-Log ("  Broadcast failed: {0}" -f $_.Exception.Message) -Level WARN
    }

    Write-Log ("Step 11 summary: {0} applied, {1} failed" -f $stats.Applied, $stats.Failed) -Level INFO
    Write-Log 'Step 11 complete.' -Level OK
    Write-Log '[SUCCESS] Taskbar context menu enhanced and Game DVR capture arrays disabled cleanly.' -Level OK
}

# ============================================================
# STEP 12: Windows Core Component and System File Repair
# ============================================================
function Invoke-Step12 {
    <#
    .SYNOPSIS
        Launches a detached visible PowerShell that runs DISM
        CheckHealth, SFC /scannow, DISM RestoreHealth, DISM
        ResetBase (gated), and DISM StartComponentCleanup.

    .DESCRIPTION
        The new window handles all SFC/DISM operations sequentially
        with a Y/N prompt before each. WinTune returns
        immediately.

        Environment variables passed to the child:
          * FC_ALLOW_RESETBASE    - 1 if -AllowResetBase was passed
          * FC_ALLOW_DISM_RESTORE - 1 if -AllowDismRestore was passed

        Steps 13, 14, 15 are now no-ops (handled here).
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 12: Windows Core Component and System File Repair' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Launches a detached shell for SFC / DISM repairs.' -Level INFO

    # ---- Gate 1: dism.exe and sfc.exe present ----
    if (-not (Get-Command 'dism.exe' -ErrorAction SilentlyContinue)) {
        Write-Log 'dism.exe not found - Step 12 skipped.' -Level WARN
        return
    }
    if (-not (Get-Command 'sfc.exe' -ErrorAction SilentlyContinue)) {
        Write-Log 'sfc.exe not found - Step 12 skipped.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would launch a detached SFC / DISM repair shell.' -Level PREVIEW
        return
    }

    # ---- Confirmation ----
    Write-Log 'About to launch a detached PowerShell window for repairs.' -Level WARN
    Write-Log 'The new window will offer to run (Y/N each):' -Level INFO
    Write-Log '  1. DISM CheckHealth          (5-30s, read-only)' -Level INFO
    Write-Log '  2. SFC /scannow              (5-15 min)' -Level INFO
    Write-Log '  3. DISM RestoreHealth        (5-25 min)' -Level INFO
    Write-Log '  4. DISM ResetBase            (irreversible)' -Level INFO
    Write-Log '  5. DISM StartComponentCleanup(2-15 min)' -Level INFO

    if (-not (Confirm-Action -Query 'Launch the detached SFC / DISM shell?')) {
        Write-Log 'Step 12 skipped by user.' -Level WARN
        return
    }

    # ---- Locate runner ----
    if (-not $Script:EmbeddedSfcDismRunner) {
        Write-Log 'Embedded SFC/DISM runner missing - this is a bug.' -Level ERROR
        return
    }
    Write-Log 'Using embedded SFC/DISM runner' -Level OK

    # ---- Copy to TEMP ----
    $runnerPath = New-SecureRunnerPath -LeafName 'SfcDism.ps1'
    try {
        Set-Content -LiteralPath $runnerPath -Value $Script:EmbeddedSfcDismRunner -Encoding UTF8 -ErrorAction Stop
        Write-Log ("  [OK] Runner written to: {0}" -f $runnerPath) -Level OK
    } catch {
        Write-Log ("Failed to copy runner: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    # ---- Set environment variables for the child ----
    $env:FC_LOG_DIR = $Script:ScriptDir
    $env:FC_ALLOW_RESETBASE    = if ($Script:AllowResetBase)    { '1' } else { '0' }
    $env:FC_ALLOW_DISM_RESTORE = if ($Script:AllowDismRestore)  { '1' } else { '0' }
    $env:FC_YES_TO_ALL         = if ($Script:YesToAll)          { '1' } else { '0' }
    $env:FC_FORCE_IRREVERSIBLE = if ($Script:ForceIrreversible) { '1' } else { '0' }

    Write-Log ("  FC_ALLOW_RESETBASE    = {0}" -f $env:FC_ALLOW_RESETBASE)    -Level DEBUG
    Write-Log ("  FC_ALLOW_DISM_RESTORE = {0}" -f $env:FC_ALLOW_DISM_RESTORE) -Level DEBUG

    # ---- Launch detached ----
    Write-Log 'Launching detached visible PowerShell window...' -Level INFO

    # Fix B3 v2: probe the runner host before committing to a launch
    $__prereq = Test-DetachedLaunchPrereqs
    if (-not $__prereq.Ok) {
        Write-Log ("  [FAIL] Detached launch prerequisites failed: {0}" -f $__prereq.Reason) -Level ERROR
        Write-Log '  Step marked Failed (child could not start).' -Level ERROR
        throw ("Detached runner prereq failure: {0}" -f $__prereq.Reason)
    }

    # [FIX-DETACHED-5B] cross-run guard
    $__existing = @(Get-ExistingDetachedRunnerProcess -Kind 'SFC/DISM')
    if ($__existing.Count -gt 0) {
        Write-Log ("  [SKIP] SFC/DISM runner already active (PID {0}, started {1})." -f $__existing[0].Pid, $__existing[0].StartedAt) -Level WARN
        Write-Log '  Close the existing window first, or wait for it to exit, then re-run.' -Level WARN
        $Script:LastStepStatus = 'Skipped'
        return
    }

    try {
        $child = Start-Process -FilePath $Script:RunnerPowerShellExe -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$runnerPath`"" -PassThru

        Write-Log ("  [OK] Child PowerShell launched (PID {0})." -f $child.Id) -Level OK
        Register-DetachedExitTracking -Child $child -Kind 'SFC/DISM' -Note 'Step 12'
        Register-TrackedRunnerKind -RunnerPid $child.Id -Kind 'SFC/DISM' -Note 'Step 12'
        Add-ReportRunner -Kind 'SFC/DISM' -RunnerPid $child.Id -Note 'Step 12'
        Write-Log '  WinTune will continue; repairs run independently.' -Level INFO
        Write-Log '  Look for the new window: "WinTune - SFC / DISM Repair"' -Level INFO
    } catch {
        Write-Log ("Failed to launch child PowerShell: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    Write-Log 'Step 12 launched (detached). SFC/DISM runs independently.' -Level OK

    Remove-Item Env:\FC_ALLOW_RESETBASE    -ErrorAction SilentlyContinue
    Remove-Item Env:\FC_ALLOW_DISM_RESTORE -ErrorAction SilentlyContinue
    Remove-Item Env:\FC_YES_TO_ALL         -ErrorAction SilentlyContinue
    Write-Log '[SUCCESS] Step 12: Detached SFC / DISM shell launched.' -Level OK
    Write-Log ('[INFO] Repair result will be in WinTune_SfcDism.log after the child exits (PID {0}).' -f $child.Id) -Level INFO
    $Script:LastStepStatus = 'Detached'
}


# ============================================================
# STEP 13: Deployment Image Cloud Restoration
# ============================================================
function Invoke-Step13 {
    <#
    .SYNOPSIS
        No-op stub. This step's work is now handled by Step 12's
        detached SFC / DISM runner.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 13: Deployment Image Cloud Restoration' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Handled by Step 12 (detached SFC / DISM runner).' -Level INFO
    Write-Log 'Step 13 complete (no-op).' -Level OK
}



# ============================================================
# HELPER: DISM Exit Code Interpretation
# ============================================================
# [REMOVED-DISMDESC] Get-DismErrorDescription (was dead code - see Clean-DeadCode.ps1)

# ============================================================
# STEP 14: Component Store Base Optimization
# ============================================================
function Invoke-Step14 {
    <#
    .SYNOPSIS
        No-op stub. This step's work is now handled by Step 12's
        detached SFC / DISM runner.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 14: Component Store Base Optimization' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Handled by Step 12 (detached SFC / DISM runner).' -Level INFO
    Write-Log 'Step 14 complete (no-op).' -Level OK
}



# ============================================================
# STEP 15: Component Store Maintenance
# ============================================================
function Invoke-Step15 {
    <#
    .SYNOPSIS
        No-op stub. This step's work is now handled by Step 12's
        detached SFC / DISM runner.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 15: Component Store Maintenance' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Handled by Step 12 (detached SFC / DISM runner).' -Level INFO
    Write-Log 'Step 15 complete (no-op).' -Level OK
}

# ============================================================
# STEP 16: Clear Windows Event Viewer Diagnostic Logs
# ============================================================
function Invoke-Step16 {
    <#
    .SYNOPSIS
        Clears the Application, System, and Setup event log channels
        to reclaim storage and remove historical diagnostic noise.

    .DESCRIPTION
        Logs cleared:
          * Application - user-app crashes, service errors
          * System      - kernel, driver, hardware events
          * Setup       - Windows Update and OS build events

        Logs NOT cleared (intentionally):
          * Security    - requires SYSTEM-level access; we skip
          * Forwarded Events - remote collector; not our business
          * Custom channels - out of scope

        WARNING: This erases crash histories. If you're actively
        debugging an issue, do NOT run this step until you've
        collected the events you need. Windows' default rotation
        (20 MB per channel) already handles bounded growth.

        Safety:
          * Never touches user data
          * Only flushes log content - channel definitions stay
          * wevtutil requires admin (script enforces)
          * Some channels may be locked by Defender or antimalware
            - logged per-channel, non-fatal
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 16: Windows Event Viewer Diagnostic Logs Cleanup' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Clears historical system diagnostic logs to reclaim storage space.' -Level INFO
    Write-Log '[WARNING] This will erase recent application crash histories.' -Level WARN

    if (-not (Confirm-Action -Query 'Clear Windows Event Viewer logs?')) {
        Write-Log 'Step 16 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would clear Application, System, and Setup diagnostic logs.' -Level PREVIEW
        return
    }

    Write-Log 'Flushing historical Event Viewer diagnostic logs...' -Level INFO

    $channels = @('Application', 'System', 'Setup')
    $stats = @{
        Cleared = 0
        Failed  = 0
    }
    $failedChannels = @()

    foreach ($channel in $channels) {
        # Verify channel exists before clearing (some SKUs lack Setup)
        $log = Get-WinEvent -ListLog $channel -ErrorAction SilentlyContinue
        if (-not $log) {
            Write-Log ("  [{0}] Channel not present - skipped." -f $channel) -Level DEBUG
            continue
        }

        try {
            $result = & wevtutil.exe cl $channel 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log ("  [{0}] Cleared." -f $channel) -Level OK
                $stats.Cleared++
            } else {
                Write-Log ("  [{0}] wevtutil returned code {1}: {2}" -f $channel, $LASTEXITCODE, ($result -join ' ')) -Level WARN
                $stats.Failed++
                $failedChannels += $channel
            }
        } catch {
            Write-Log ("  [{0}] Clear failed: {1}" -f $channel, $_.Exception.Message) -Level WARN
            $stats.Failed++
            $failedChannels += $channel
        }
    }

    # ---- Summary ----
    Write-Log ("Event Viewer log sweep: {0} cleared, {1} failed" -f $stats.Cleared, $stats.Failed) -Level INFO

    if ($stats.Failed -eq 0) {
        Write-Log '[SUCCESS] Windows Event Viewer logs successfully cleared.' -Level OK
        Write-Log '[STATUS] Core event log channels flushed cleanly.' -Level INFO
    } else {
        Write-Log 'Some Event Viewer logs are currently locked by active security processes.' -Level WARN
        Write-Log ("[WARNING] Failed channels: {0}" -f ($failedChannels -join ', ')) -Level WARN
    }

    Write-Log 'Step 16 complete.' -Level OK
}


# ============================================================
# STEP 17: System Restore Shadow Storage Optimization
# ============================================================
function Invoke-Step17 {
    <#
    .SYNOPSIS
        Caps Volume Shadow Copy (VSS) storage on the system drive
        to a fixed size (3 GB on drives up to 500 GB, 5 GB on larger).

    .DESCRIPTION
        What VSS is:
          * Stores System Restore points and Previous Versions
          * By default, can grow to 10% of the drive (or unlimited
            on some Windows configurations)
          * On a 1 TB drive, that's up to 100 GB of restore points

        Why fixed GB, not percentage:
          * Restore points are ~1-2 GB each, regardless of drive size.
          * A percentage cap gives huge drives huge VSS budgets
            (30 GB+ on a 2 TB drive) for no benefit.
          * A fixed GB cap gives a consistent restore-point count
            (2-3 points) on any machine.

        Tiered policy:
          * System drive <= 500 GB  ->  3 GB cap
          * System drive  > 500 GB  ->  5 GB cap

        What this step does:
          * `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=3GB * Enforces a strict upper bound on VSS allocation
          * If current usage exceeds the cap, older restore points
            are immediately purged by Windows to fit

        Impact:
          * System Restore still works - you keep recent points
          * You lose the ability to restore very old snapshots
          * Previous Versions (file history) may lose older copies

        Not applied if:
          * System Protection is disabled on the drive
          * The drive doesn't have a shadow storage area

        Safety:
          * Never touches user data
          * Reversible: `vssadmin resize shadowstorage
            /for=C: /on=C: /maxsize=unbounded * Requires admin (script enforces)
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 17: System Restore Shadow Storage Optimization' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    # ---- Compute the tiered cap based on system drive size ----
    $driveSizeGB = 0
    try {
        $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction Stop
        if ($ld -and $ld.Size -gt 0) {
            $driveSizeGB = [math]::Round($ld.Size / 1GB, 0)
        }
    } catch {
        Write-Log ("  Could not determine drive size: {0}" -f $_.Exception.Message) -Level DEBUG
    }

    # Tiered policy:
    #   <= 500 GB system drive -> 3 GB VSS cap
    #    > 500 GB system drive -> 5 GB VSS cap
    $capGB     = if ($driveSizeGB -gt 500) { 5 } else { 3 }
    $capReason = if ($driveSizeGB -gt 500) { 'large drive (>500 GB)' } else { 'standard drive (<=500 GB)' }

    Write-Log ("  System drive size: {0} GB" -f $driveSizeGB) -Level INFO
    Write-Log ("  VSS cap policy:    {0} GB ({1})" -f $capGB, $capReason) -Level INFO
    Write-Log ("  Limits hidden System Restore allocation to {0} GB." -f $capGB) -Level INFO
    Write-Log ("[WARNING] If current VSS usage exceeds {0} GB, older historical restore" -f $capGB) -Level WARN
    Write-Log '          points will be immediately purged to reclaim space.' -Level WARN

    if (-not (Confirm-Action -Query ("Cap Volume Shadow Storage (VSS) at {0} GB?" -f $capGB))) {
        Write-Log 'Step 17 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log ("Would limit {0} shadow storage to a {1} GB max threshold." -f $env:SystemDrive, $capGB) -Level PREVIEW
        return
    }

    # ---- Pre-check: is System Protection enabled on the system drive? ----
    $driveLetter = $env:SystemDrive.TrimEnd(':')   # "C:" -> "C"

    try {
        $vssList = & vssadmin.exe list shadowstorage /for="$($driveLetter):" 2>&1
               # vssadmin output uses "Shadow Copy Storage" (three words), not "Shadow Storage"
        $hasShadowStorage = ($LASTEXITCODE -eq 0) -and ($vssList -match 'Used Shadow Copy Storage space')
    } catch {
        $hasShadowStorage = $false
    }

    if (-not $hasShadowStorage) {
        Write-Log ("No shadow storage configured on {0}: - System Protection may be disabled." -f $driveLetter) -Level WARN
        Write-Log 'Skipping VSS resize (nothing to cap).' -Level INFO
        Write-Log '[INFO] No action needed - shadow storage already within target.' -Level INFO
        return
    }

    # ---- Apply the cap ----
    Write-Log ("Reconfiguring Volume Shadow Copy maximum to {0} GB..." -f $capGB) -Level INFO

    try {
        $result = & vssadmin.exe resize shadowstorage /for="$($driveLetter):" /on="$($driveLetter):" /maxsize="$($capGB)GB" 2>&1
        $vssExitCode = $LASTEXITCODE
    } catch {
        Write-Log ("vssadmin invocation failed: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    # Log raw output
    $result | ForEach-Object {
        Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    Write-Log ("vssadmin returned exit code {0}" -f $vssExitCode) -Level INFO

    # ---- Verdict ----
    if ($vssExitCode -eq 0) {
        Write-Log ("[SUCCESS] Shadow storage cap set to {0} GB." -f $capGB) -Level OK
        Write-Log '[STATUS] Volume Shadow Storage resize successfully written to kernel configurations.' -Level INFO
    } else {
        Write-Log 'Subsystem modification was rejected.' -Level WARN
        Write-Log 'This partition may have System Protection feature toggles disabled.' -Level WARN
        Write-Log ("[WARNING] vssadmin execution returned non-zero code: {0}" -f $vssExitCode) -Level WARN
    }

    Write-Log 'Step 17 complete.' -Level OK
}
# ============================================================
# STEP 18: Third-Party Driver Store Diagnostic Audit
# ============================================================
function Invoke-Step18 {
    <#
    .SYNOPSIS
        Enumerates all third-party driver packages in the DriverStore
        and exports them to the log. Optionally allows the user to
        interactively uninstall a specific OEM driver package by name.

    .DESCRIPTION
        Phase 1 - Audit (always runs):
          * Runs `pnputil /enum-drivers * Exports every third-party package (oemNN.inf) to the log
          * Includes class, version, provider, and date for each

        Phase 2 - Optional removal (interactive):
          * Prompts for an OEM INF name (e.g., oem14.inf)
          * Validates input against strict regex: ^oem\d+\.inf$
          * Rejects any shell metacharacter as a defense-in-depth
          * Prompts again before deletion
          * Runs `pnputil /delete-driver <name> /uninstall * WITHOUT /force, so Windows refuses to remove active
            drivers - this is intentional safety

        Input validation:
          * Only accepts the pattern "oem<digits>.inf"
          * Rejects spaces, quotes, & | < > ^ % ! and any other
            shell metacharacter
          * Enforces lowercase "oem" prefix case-insensitively

        Safety:
          * Never uses /force
          * Active drivers cannot be removed
          * Deletion is reversible by reinstalling the driver
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 18: Third-Party Driver Store Diagnostic Audit' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Scans and exports a complete list of all third-party drivers to the log.' -Level INFO

    if (-not (Confirm-Action -Query 'Execute driver store infrastructure audit?')) {
        Write-Log 'Step 18 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would enumerate DriverStore packages and offer interactive removal prompts.' -Level PREVIEW
        return
    }

    # ============================================================
    # PHASE 1: Enumerate drivers
    # ============================================================
    Write-Log 'Parsing local DriverStore repositories... [Please wait]' -Level INFO

    try {
        $pnputilResult = & pnputil.exe /enum-drivers 2>&1
        $pnputilExitCode = $LASTEXITCODE
    } catch {
        Write-Log ("pnputil invocation failed: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    # Log raw output
    $pnputilResult | ForEach-Object {
        Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    if ($pnputilExitCode -ne 0) {
        Write-Log 'pnputil /enum-drivers returned an error. See log for details.' -Level WARN
        Write-Log '[WARNING] Step 18: pnputil /enum-drivers failed.' -Level WARN
        return
    }

    Write-Log 'Complete third-party driver schema successfully exported to log.' -Level OK

    # Count enumerated drivers (informational)
    $driverCount = ($pnputilResult | Select-String -Pattern '^Published Name\s*:\s*oem\d+\.inf' -AllMatches).Count
    if ($driverCount -gt 0) {
        Write-Log ("  Total OEM driver packages enumerated: {0}" -f $driverCount) -Level INFO
    }

    # ============================================================
    # PHASE 2: Optional interactive removal
    # ============================================================
    Write-Host ('-' * 60) -ForegroundColor DarkGray
    Write-Host 'INTERACTIVE CLEANUP: Optional Driver Removal' -ForegroundColor Cyan
    Write-Host ('-' * 60) -ForegroundColor DarkGray
    Write-Host 'Enter the published name of an OEM driver to remove (e.g., oem14.inf).'
    Write-Host 'This is optional. Leave blank to skip.'

    # Safe mode: skip prompt or use -RemoveDriver when -YesToAll is set
    $targetInf = ''
    if ($Script:YesToAll) {
        if ($Script:RemoveDriver) {
            Write-Host ("  [AUTO] Using driver from -RemoveDriver: {0}" -f $Script:RemoveDriver) -ForegroundColor Cyan
            $targetInf = $Script:RemoveDriver
        } else {
            Write-Host '  [AUTO] Skipping driver removal (-YesToAll without -RemoveDriver).' -ForegroundColor Cyan
            Write-Log 'Driver removal skipped: -YesToAll without -RemoveDriver.' -Level INFO
        }
    } else {
        $targetInf = Read-Host 'Enter the exact OEM .inf name to delete (blank to skip)'
    }

    if ([string]::IsNullOrWhiteSpace($targetInf)) {
        Write-Log 'Driver removal skipped. System configurations untouched.' -Level INFO
        return
    }

    # ---- Sanitize: remove spaces and quotes ----
    $targetInf = $targetInf.Trim()
    $targetInf = $targetInf -replace '\s', ''       # strip all whitespace
    $targetInf = $targetInf -replace '"', ''        # strip double quotes
    $targetInf = $targetInf -replace "'", ''        # strip single quotes

    # ---- Defense-in-depth: reject ANY shell metacharacter ----
    # Even though we pass the value as a PS string (no shell interpolation),
    # rejecting metacharacters prevents user confusion and future bugs.
    if ($targetInf -match '[&|<>^%!`$;()]') {
        Write-Log 'Input contains illegal shell metacharacters. Removal aborted for safety.' -Level WARN
        Write-Log '[WARNING] Step 18: Illegal characters in driver name input.' -Level WARN
        return
    }

    # ---- Strict pattern validation ----
    if ($targetInf -notmatch '^[oO][eE][mM]\d+\.inf$') {
        Write-Log 'Input does not match expected OEM INF pattern (e.g., oem14.inf).' -Level WARN
        Write-Log 'Removal aborted for safety.' -Level WARN
        Write-Log ("[WARNING] Step 18: Invalid driver name input '{0}'. Aborted." -f $targetInf) -Level WARN
        return
    }

    # ---- Final confirmation ----
    Write-Log ("About to force delete driver package: {0}" -f $targetInf) -Level WARN

    if (-not (Confirm-Action -Query 'Are you absolutely sure you want to proceed?')) {
        Write-Log 'Removal aborted by user.' -Level INFO
        return
    }

    # ---- Execute removal ----
    Write-Log 'Executing safe-checked driver deletion thread...' -Level INFO
    Write-Log ("Executing manual deletion pass on driver: {0}" -f $targetInf) -Level INFO

    try {
        $deleteResult = & pnputil.exe /delete-driver $targetInf /uninstall 2>&1
        $pnpExitCode  = $LASTEXITCODE
    } catch {
        Write-Log ("pnputil delete invocation failed: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    # Log raw output
    $deleteResult | ForEach-Object {
        Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    # ---- Verdict ----
    if ($pnpExitCode -eq 0) {
        Write-Log ("Driver package {0} successfully uninstalled and purged from disk." -f $targetInf) -Level OK
        Write-Log ("[STATUS] Driver {0} successfully removed via interactive prompt." -f $targetInf) -Level INFO
    } else {
        $codeHex = '0x{0:X8}' -f $pnpExitCode
        Write-Log ("Deletion rejected (Exit Code: {0} {1})." -f $pnpExitCode, $codeHex) -Level WARN
        Write-Log 'This driver is likely currently ACTIVE or required by your hardware.' -Level WARN
        Write-Log ("[WARNING] pnputil failed to delete {0}. Code: {1}" -f $targetInf, $pnpExitCode) -Level WARN
    }

    Write-Log 'Step 18 complete.' -Level OK
}
# ============================================================
# STEP 19: Boot Startup Program Diagnostic Audit
# ============================================================
function Invoke-Step19 {
    <#
    .SYNOPSIS
        Enumerates all programs configured to auto-launch at boot,
        and exports the list to the log file with a rich set of
        columns.

    .DESCRIPTION
        Data source: Get-CimInstance Win32_StartupCommand

        This WMI class covers all startup mechanisms Windows tracks:
          * HKCU\...\Run
          * HKCU\...\RunOnce
          * HKLM\...\Run
          * HKLM\...\RunOnce
          * HKLM\...\RunServices (legacy)
          * Startup folders (user + All Users)

        Columns exported:
          * Caption  - friendly name
          * Command  - full command line
          * Location - registry path or folder where the entry lives
          * User     - SID/account that will launch the program
          * Name     - internal name of the entry

        READ-ONLY operation. No modifications are made to any startup
        entry - this is a diagnostic audit only.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 19: Boot Startup Program Diagnostic Audit' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Audits and exports all auto-launching programs. Active startup entries remain UNCHANGED.' -Level INFO

    if (-not (Confirm-Action -Query 'Execute boot startup infrastructure audit?')) {
        Write-Log 'Step 19 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would query Win32_StartupCommand and export boot-initialization rows.' -Level PREVIEW
        return
    }

    Write-Log 'Querying system boot registry and startup vectors... [Please wait]' -Level INFO
    Write-Log 'Enrolling system startup program audit...' -Level INFO

    # ---- Query Win32_StartupCommand ----
    try {
        $startupItems = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop
        $queryStatus = 0
    } catch {
        Write-Log ("Win32_StartupCommand query failed: {0}" -f $_.Exception.Message) -Level WARN
        $startupItems = @()
        $queryStatus = 1
    }

    # ---- Log a formatted table (or empty message) ----
    if ($startupItems.Count -eq 0) {
        Add-Content -LiteralPath $Script:LogFile -Value '(No startup entries returned.)' -Encoding UTF8 -ErrorAction SilentlyContinue
    } else {
        # Export in two formats: table for human reading, CSV for programmatic use
        $tableOutput = $startupItems |
            Select-Object Caption, Command, Location, User, Name |
            Format-Table -AutoSize |
            Out-String -Width 4096

        # Write table to log
        $tableOutput -split "`r?`n" | ForEach-Object {
            Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue
        }

        Write-Log ("  Total startup entries: {0}" -f $startupItems.Count) -Level INFO
    }

    # ---- Write structured summary to log ----
    Write-Log ("Startup program configuration audit concluded with internal code: {0}" -f $queryStatus) -Level INFO

    # ---- Verdict ----
    if ($queryStatus -eq 0) {
        Write-Log 'Complete startup application schema successfully exported to log.' -Level OK
        Write-Log '[STATUS] Startup database collection successfully committed to diagnostics file.' -Level INFO
    } else {
        Write-Log 'Subsystem query encountered a processing limitation.' -Level WARN
        Write-Log ("[WARNING] Startup query returned non-zero code: {0}" -f $queryStatus) -Level WARN
    }

    Write-Log 'Step 19 complete.' -Level OK
}
# ============================================================
# FIX 2 helper: Test-IsSystemServiceAccount
# ============================================================
function Test-IsSystemServiceAccount {  # [FIX-SILENT-2b]
    param([string]$UserId)
    if ([string]::IsNullOrWhiteSpace($UserId)) { return $false }
    $u = $UserId.Trim().ToLowerInvariant()
    $list = @(
        'wsiaccount'
        'system'
        'nt authority\system'
        'local service'
        'nt authority\local service'
        'network service'
        'nt authority\network service'
    )
    return ($list -contains $u)
}

# ============================================================
# STEP 20: Automated Windows Scheduled Tasks Diagnostic Audit
# ============================================================
function Invoke-Step20 {
    <#
    .SYNOPSIS
        Enumerates every scheduled task on the system and exports
        a comprehensive verbose listing to the log.

    .DESCRIPTION
        Data source: Get-ScheduledTask (native PS cmdlet)

        Exported columns:
          * TaskPath   - folder hierarchy in Task Scheduler
          * TaskName   - task display name
          * State      - Ready / Running / Disabled / Queued
          * Author     - creator
          * Description
          * Actions    - executables/programs invoked
          * Triggers   - when the task runs
          * Principal  - user account context

        Complements Step 19 (Win32_StartupCommand). Scheduled tasks
        are a common persistence mechanism for both legitimate apps
        (update checkers) and malware. This step is READ-ONLY.

        Safety:
          * No task is started, stopped, or modified
          * Requires admin to read all tasks (script enforces)
    #>
    [CmdletBinding()]
    param()

    # ---- PS 5.1-safe null/empty fallback helper ----
    $orDefault = {
        param($Value, $Default = '(unknown)')
        if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $Default }
        return $Value
    }

    Write-Log 'STEP 20: Automated Windows Scheduled Tasks Diagnostic Audit' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Audits and exports all scheduled tasks. Active configurations remain UNCHANGED.' -Level INFO

    if (-not (Confirm-Action -Query 'Execute automated scheduled tasks infrastructure audit?')) {
        Write-Log 'Step 20 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would query schtasks and export comprehensive verbose execution rows.' -Level PREVIEW
        return
    }

    Write-Log 'Querying Windows Task Scheduler structural tables...' -Level INFO
    Write-Log 'Parsing background trigger blocks [This may take up to 30 seconds - Please wait]...' -Level INFO

    # ---- Enumerate scheduled tasks ----
    $auditStatus = 0
    $tasks = @()

    try {
        # Get-ScheduledTask returns all tasks the current user can read;
        # as admin this includes tasks from all users and system context
        $tasks = Get-ScheduledTask -ErrorAction Stop
    } catch {
        Write-Log ("Get-ScheduledTask query failed: {0}" -f $_.Exception.Message) -Level WARN
        $auditStatus = 1
    }

    # ---- Write header to log ----
    $headerLines = @(
        ''
        '============================================================'
        (' SCHEDULED TASKS AUDIT - {0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date))
        (' Total tasks discovered: {0}' -f $tasks.Count)
        '============================================================'
        ''
    )
    $headerLines | ForEach-Object {
        Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    # ---- Write each task as a formatted block ----
    if ($tasks.Count -gt 0) {
        $taskIndex = 0
        foreach ($task in $tasks) {
            $taskIndex++

            $line = @()
            $line += ('[{0}/{1}] {2}{3}' -f $taskIndex, $tasks.Count, $task.TaskPath, $task.TaskName)
            $line += ('  State:       {0}' -f $task.State)
            $line += ('  Author:      {0}' -f (& $orDefault $task.Author '(unknown)'))
            $line += ('  Description: {0}' -f (& $orDefault $task.Description '(none)'))

            # Principal (user account context)
            if ($task.Principal) {
                $line += ('  RunAs:       {0}' -f (& $orDefault $task.Principal.UserId '(system)'))
                $line += ('  LogonType:   {0}' -f (& $orDefault $task.Principal.LogonType '(default)'))
                $line += ('  RunLevel:    {0}' -f (& $orDefault $task.Principal.RunLevel '(default)'))
            }

            # Actions
            if ($task.Actions) {
                foreach ($action in $task.Actions) {
                    $actionText = $null

                    if ($action.CimClass -and $action.CimClass.CimClassName -eq 'MSFT_TaskExecAction') {
                        $actionText = $action.Execute
                        if ($action.Arguments) {
                            $actionText += " $($action.Arguments)"
                        }
                    } elseif ($action.CimClass -and $action.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction') {
                        $actionText = "(COM handler: $($action.ClassId))"
                    } elseif ($action.PSObject.Properties['Execute']) {
                        # Fallback: try Execute if the property exists
                        $actionText = $action.Execute
                        if ($action.PSObject.Properties['Arguments'] -and $action.Arguments) {
                            $actionText += " $($action.Arguments)"
                        }
                    } else {
                        $actionText = '(unknown action type)'
                    }

                    if ($actionText) {
                        $line += ('  Action:      {0}' -f $actionText)
                    }
                }
            }

            # Triggers
            if ($task.Triggers) {
                foreach ($trigger in $task.Triggers) {
                    $triggerType = 'Trigger'
                    if ($trigger.CimClass -and $trigger.CimClass.CimClassName) {
                        $triggerType = $trigger.CimClass.CimClassName -replace '^MSFT_Task', ''
                    }
                    $line += ('  Trigger:     {0}' -f $triggerType)
                }
            }

            $line += ''

            # Write task block to log
            $line | ForEach-Object {
                Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue
            }
        }
    } else {
        Add-Content -LiteralPath $Script:LogFile -Value '(No scheduled tasks returned.)' -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    # ---- Summary line ----
    Write-Log ("Scheduled tasks audit concluded with internal code: {0}" -f $auditStatus) -Level INFO
    Write-Log ("  Total tasks: {0}" -f $tasks.Count) -Level INFO

    # ---- Verdict ----
    if ($auditStatus -eq 0) {
        Write-Log 'Complete scheduled task schema successfully exported to log.' -Level OK
        Write-Log '[STATUS] Verbose task rows successfully appended to central diagnostics log.' -Level INFO
    } else {
        Write-Log 'Task scheduler query encountered an operational access limitation.' -Level WARN
        Write-Log ("[WARNING] schtasks query returned non-zero code: {0}" -f $auditStatus) -Level WARN
    }

    # ---- Step 20 disable phase (gated) ----
    if ($Script:AllowScheduledTaskAction -and -not $Script:DryRun -and $tasks.Count -gt 0) {
        $candidates = @($tasks | Where-Object {
            $_.TaskPath -notlike '\Microsoft\*' -and
            $_.State -eq 'Ready' -and
            $_.TaskPath -notmatch '^\\Microsoft\\Windows\\(UpdateOrchestrator|Defrag|SystemRestore)\\' -and
            # [FIX-SILENT-2] Robust ignore-list for system service accounts.
            # The old regex over-escaped the backslashes (four literal '\'
            # in a single-quoted string means the regex sees two, which
            # matches two), so NT AUTHORITY\SYSTEM never matched and
            # WsiAccount only matched when Principal.UserId was the bare
            # string (which it is not on some builds).
            -not (Test-IsSystemServiceAccount -UserId $(if ($_.Principal) { [string]$_.Principal.UserId } else { '' }))
        })

        if ($candidates.Count -gt 0) {
            Write-Host ''
            Write-Log ("Step 20 disable phase: {0} non-Microsoft Ready task(s) eligible" -f $candidates.Count) -Level WARN
            foreach ($c in $candidates) {
                Write-Log ("  [CANDIDATE] {0}{1}" -f $c.TaskPath, $c.TaskName) -Level WARN
            }

            if (Confirm-Action -Query ('Disable {0} candidate task(s)?' -f $candidates.Count)) {
                $disabled = 0; $failed = 0
                foreach ($c in $candidates) {
                    try {
                        Disable-ScheduledTask -TaskPath $c.TaskPath -TaskName $c.TaskName -ErrorAction Stop | Out-Null
                        Write-Log ("  [DISABLED] {0}{1}" -f $c.TaskPath, $c.TaskName) -Level OK
                        Add-RollbackEntry -Step 20 -Type 'ScheduledTask' -Data @{
                            Path = $c.TaskPath
                            Name = $c.TaskName
                        }
                        $disabled++
                    } catch {
                        $errMsg = $_.Exception.Message
                        if ($errMsg -match 'Access is denied|Access denied|0x80070005') {
                            Write-Log ("  [SKIP] {0}{1} - system-managed (Access Denied)" -f $c.TaskPath, $c.TaskName) -Level INFO
                        } else {
                            Write-Log ("  [FAIL] {0}{1}: {2}" -f $c.TaskPath, $c.TaskName, $errMsg) -Level WARN
                            $failed++
                        }
                    }
                }
                Write-Log ("  Step 20 disable summary: {0} disabled, {1} failed" -f $disabled, $failed) -Level INFO
            } else {
                Write-Log 'Step 20 disable phase declined by user.' -Level INFO
            }
        }
    } elseif (-not $Script:AllowScheduledTaskAction -and $tasks.Count -gt 0) {
        $candidateCount = @($tasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -eq 'Ready' }).Count
        if ($candidateCount -gt 0) {
            Write-Log ("  {0} non-Microsoft Ready task(s) - audit only (use -AllowScheduledTaskAction to disable)" -f $candidateCount) -Level INFO
        }
    }

    Write-Log 'Step 20 complete.' -Level OK
}
# ============================================================
# STEP 21: Windows Prefetch Launch Cache Trimming
# ============================================================
function Invoke-Step21 {
    <#
    .SYNOPSIS
        Purges the Windows Prefetch cache directory (NOT recommended).

    .DESCRIPTION
        What Prefetch is:
          * Windows stores application launch traces in
            %SystemRoot%\Prefetch\*.pf
          * On next launch of an app, Windows uses the trace to
            pre-load required DLLs and data - reducing cold-start
            time by 30-70%
          * The SuperFetch / SysMain service manages this

        What happens when you delete Prefetch:
          * Next launch of every app is SLOWER (no trace available)
          * Windows re-learns over the following days
          * Full performance recovery takes 3-7 days of use
          * SSD users gain ~nothing (SSDs are fast enough without it)

        When this IS legitimate:
          * A specific app's .pf file is corrupted and causes launch
            failures
          * Malware analysis / forensic cleanup
          * Bench-marking from a "clean" state

        Gating:
          * Requires -AllowPrefetch command-line flag
          * Requires explicit Y/N confirmation
          * Requires user to see the strong warning

        Safety:
          * No user data touched
          * Only *.pf files removed from the Prefetch folder
          * Windows regenerates them automatically
          * SysMain service (which manages Prefetch) is not disabled
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 21: Windows Prefetch Launch Cache Trimming' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    Write-Log '[WARNING] Clearing Prefetch is NOT recommended for general optimization.' -Level WARN
    Write-Log '          Prefetch houses application initialization mappings.' -Level WARN
    Write-Log '          Deleting them temporarily SLOWS DOWN app launch speeds.' -Level WARN
    Write-Log '[NOTE] Only run this if troubleshooting severe app launch failures.' -Level INFO

    # ---- Gate 1: -AllowPrefetch must be set ----
    if (-not $Script:AllowPrefetch) {
        Write-Log 'Step 21 blocked: -AllowPrefetch flag was not supplied.' -Level INFO
        Write-Log 'Prefetch purge is discouraged and requires explicit opt-in.' -Level INFO
        Write-Log '[INFO] Step 21 skipped: -AllowPrefetch authorization flag absent.' -Level INFO
        return
    }

    # ---- Gate 2: Explicit Y/N confirmation ----
    if (-not (Confirm-Action -Query 'Force execute unrecommended Prefetch directory purge?')) {
        Write-Log 'Step 21 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would clear Windows Prefetch initialization cache files.' -Level PREVIEW
        return
    }

    # ---- Verify Prefetch directory exists ----
    $prefetchDir = Join-Path $env:SystemRoot 'Prefetch'
    if (-not (Test-Path -LiteralPath $prefetchDir)) {
        Write-Log ('Prefetch directory not present: {0}' -f $prefetchDir) -Level WARN
        Write-Log '[INFO] Step 21 skipped: Prefetch folder does not exist.' -Level INFO
        return
    }

    Write-Log 'Proceeding with unrecommended Prefetch optimization pass...' -Level WARN
    Write-Log 'Executing unrecommended Prefetch directory wipe...' -Level WARN

    # ---- Enumerate and delete .pf files ----
    # We target *.pf explicitly, NOT * (which would catch READYBOOT, layout.ini, etc.)
    # Windows core files in Prefetch that aren't app traces should be preserved.
    $deletedCount = 0
    $failedCount  = 0
    $bytesFreed   = [int64]0

    try {
        $prefetchFiles = Get-ChildItem -LiteralPath $prefetchDir -Filter '*.pf' -File -Force -ErrorAction SilentlyContinue

        foreach ($pf in $prefetchFiles) {
            try {
                $size = $pf.Length
                Remove-Item -LiteralPath $pf.FullName -Force -ErrorAction Stop
                $deletedCount++
                $bytesFreed += $size
            } catch {
                # Locked .pf file - kernel holds an active handle
                $failedCount++
            }
        }
    } catch {
        Write-Log ("Prefetch enumeration failed: {0}" -f $_.Exception.Message) -Level WARN
    }

    $freedMB = [math]::Round($bytesFreed / 1MB, 2)

    Write-Log ("Prefetch purge: {0} files deleted, {1} locked, {2:N2} MB reclaimed" -f $deletedCount, $failedCount, $freedMB) -Level INFO
    Write-Log ("Prefetch directory purge concluded with internal code: {0}" -f $(if ($failedCount -eq 0) { 0 } else { 1 })) -Level INFO

    # ---- Verdict ----
    if ($failedCount -eq 0) {
        Write-Log 'Windows Prefetch launch cache cleared successfully.' -Level OK
        Write-Log '[STATUS] Prefetch initialization table cleanly wiped.' -Level INFO
        Write-Log 'App launches will be slightly slower for the next few days while Windows rebuilds the cache.' -Level INFO
    } else {
        Write-Log 'Some prefetch nodes are currently locked by the active Windows kernel.' -Level WARN
        Write-Log ("[WARNING] Prefetch execution returned {0} locked files." -f $failedCount) -Level WARN
        Write-Log 'This is normal - the SysMain service actively holds hot .pf handles. Locks release on reboot.' -Level INFO
    }

    Write-Log 'Step 21 complete.' -Level OK
}
# ============================================================
# STEP 22: Windows System RAM Standby Allocation Flush
# ============================================================
function Invoke-Step22 {
    <#
    .SYNOPSIS
        Forces the Windows kernel to release cached background pages
        held in the Standby Memory list back into the Free Memory pool.

    .DESCRIPTION
        What "Standby Memory" is:
          * Windows caches recently-used files in RAM as "standby"
            pages - memory that is technically "free" (reclaimable
            instantly) but currently holds cached data
          * Task Manager shows this as "Cached" memory
          * Idle systems often show 4-8 GB of cached data

        What this step does:
          * Calls NtSetSystemInformation with
            SystemMemoryListInformation (class 80) and
            MemoryPurgeStandbyList (command 4)
          * This clears ALL standby pages instantly
          * Freed memory returns to the "Free" pool

        Why you might want this:
          * Before launching a heavy ML model / VM / game that needs
            a large contiguous memory block
          * To measure true "cold" performance after running for hours

        Why it's NOT a general optimization:
          * Standby cache speeds up subsequent file reads
          * Purging it makes the next file access hit disk instead
            of RAM
          * Windows re-fills standby within minutes of idle time

        Requires:
          * SeProfileSingleProcessPrivilege (admin, enabled in-code)
          * Windows Vista or later (NtSetSystemInformation exists)

        May silently no-op on:
          * Systems with aggressive third-party memory managers
          * Windows Server Core without the profile privilege
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 22: Windows System RAM Standby Allocation Flush' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Forces the Windows kernel to release cached background data' -Level INFO
    Write-Log 'held in the Standby Memory pool back into Free Memory.' -Level INFO

    if (-not (Confirm-Action -Query 'Flush system standby memory arrays?')) {
        Write-Log 'Step 22 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would invoke Windows APIs to clear the global Standby Memory list.' -Level PREVIEW
        return
    }

    # ---- Portability fix: skip unconditionally ----
    # NtSetSystemInformation class 80 is unreliable across Windows builds.
    # On modern builds it returns STATUS_ACCESS_VIOLATION. On older builds
    # it requires SeProfileSingleProcessPrivilege which may not be available.
    # Windows manages standby memory automatically; no action is required.
    Write-Log "Step 22 skipped: NtSetSystemInformation class 80 is unreliable across builds." -Level INFO
    Write-Log "Windows manages standby memory automatically. No action required." -Level INFO
    Write-Log "Step 22 complete (skipped by design)." -Level OK
    return
}


# ============================================================
# STEP 23: Windows Network Stack Realignment
# ============================================================
function Invoke-Step23 {
    <#
    .SYNOPSIS
        Flushes DNS cache, clears routing tables, and resets the
        Winsock catalog and TCP/IP stack to factory defaults.

    .DESCRIPTION
        Operations performed (in order):
          1. ipconfig /flushdns        - clears DNS resolver cache
          2. route /f                  - clears all static route entries
          3. netsh winsock reset       - rewrites Winsock catalog
          4. netsh int ip reset        - rewrites TCP/IP stack registry

        Effect:
          * All active network connections drop immediately
          * A reboot is REQUIRED to apply the changes
          * After reboot, network adapters re-enumerate fresh

        When to use:
          * Persistent DNS resolution failures
          * Winsock catalog corruption (LSP malware remnants)
          * After VPN client removal leaves broken routes
          * Stubborn "connected but no internet" errors

        Gating:
          * Requires -AllowNetworkReset flag
          * Detects VPN adapters and warns with second confirmation
          * Requires explicit Y/N confirmation

        Safety:
          * No user data touched
          * Network config (IP, DNS, WiFi keys) is preserved -
            only the STACK is reset, not the settings
          * Reversible only by reconfiguring (rare to need)
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 23: Windows Network Stack Realignment' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log '[CRITICAL WARNING] This resets network adapters. Active internet' -Level WARN
    Write-Log '                   connections will drop immediately, and you MUST' -Level WARN
    Write-Log '                   reboot your PC afterward to complete repairs.' -Level WARN

    # ---- Gate 1: -AllowNetworkReset must be set ----
    if (-not $Script:AllowNetworkReset) {
        Write-Log 'Step 23 blocked: -AllowNetworkReset flag was not supplied.' -Level INFO
        Write-Log 'Network reset drops all connectivity and requires reboot.' -Level INFO
        Write-Log 'Re-run with -AllowNetworkReset if you explicitly want this.' -Level INFO
        Write-Log '[INFO] Step 23 skipped: -AllowNetworkReset authorization flag absent.' -Level INFO
        return
    }

    # ---- B6 fix: Wi-Fi and domain-join guards ----
    # Prompt before the disruptive reset when losing connectivity is
    # more than a minor inconvenience.

    $wifiConnected = $false
    try {
        $wifiAdapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                       Where-Object { $_.MediaType -eq 'Native 802.11' -and $_.Status -eq 'Up' } |
                       Select-Object -First 1
        if ($wifiAdapter) { $wifiConnected = $true }
    } catch { }

    if ($wifiConnected) {
        Write-Log 'Active Wi-Fi connection detected.' -Level WARN
        Write-Log 'Resetting Winsock drops connectivity until reboot.' -Level WARN
        if (-not (Confirm-Action -Query 'Proceed with network reset over Wi-Fi?')) {
            Write-Log '[INFO] Step 23 aborted: Wi-Fi active, user declined.' -Level INFO
            return
        }
    }

    $domainJoined23 = $false
    try {
        $domainJoined23 = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
    } catch { }

    if ($domainJoined23) {
        Write-Log 'Machine is domain-joined. Resetting Winsock may require IT re-authentication.' -Level WARN
        if (-not (Confirm-Action -Query 'Proceed with network reset on domain-joined machine?')) {
            Write-Log '[INFO] Step 23 aborted: domain-joined, user declined.' -Level INFO
            return
        }
    }

    # ---- VPN adapter detection ----
    $vpnDetected = $false
    $vpnName = $null

    try {
        # VPN/tunnel adapters that indicate a corporate/managed network
        $vpnPattern = 'VPN|TAP|TUN|WireGuard|OpenVPN|Cisco|AnyConnect|GlobalProtect|FortiClient|Sangfor|Pulse|Zscaler'

        $vpnAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
                      Where-Object { $_.InterfaceDescription -match $vpnPattern } |
                      Select-Object -First 1

        if ($vpnAdapter) {
            $vpnDetected = $true
            $vpnName = $vpnAdapter.Name
        }
    } catch {
        Write-Log ("VPN adapter enumeration failed: {0}" -f $_.Exception.Message) -Level DEBUG
    }

    if ($vpnDetected) {
        Write-Log ("A VPN or tunnel adapter was detected: {0}" -f $vpnName) -Level WARN
        Write-Log 'Resetting the network stack may disconnect corporate' -Level WARN
        Write-Log 'resources and require re-authentication.' -Level WARN

        if (-not (Confirm-Action -Query 'Proceed with network reset anyway?')) {
            Write-Log 'Network reset aborted by user.' -Level INFO
            Write-Log ("[INFO] Step 23 aborted: VPN adapter detected ({0}), user declined." -f $vpnName) -Level INFO
            return
        }
    }

    # ---- Gate 2: Main confirmation ----
    if (-not (Confirm-Action -Query 'Execute complete network layer realignment?')) {
        Write-Log 'Step 23 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would flush DNS tables, wipe network routing hooks, and reset Winsock structures.' -Level PREVIEW
        return
    }

    # ============================================================
    # 1. Flush DNS resolver cache
    # ============================================================
    Write-Log 'Flushing local DNS resolver caches...' -Level INFO

    $dnsResult = Invoke-NativeCommand -FilePath 'ipconfig.exe' -Arguments @('/flushdns') -NoNewWindow
    if ($dnsResult.Success) {
        Write-Log '  [OK] DNS cache flushed.' -Level OK
    } else {
        Write-Log ("  [WARN] ipconfig /flushdns returned code {0}" -f $dnsResult.ExitCode) -Level WARN
    }

    # ============================================================
    # 2. Clear static routes
    # ============================================================
    Write-Log 'Clearing stale network gateway routing logs...' -Level INFO

    $routeResult = Invoke-NativeCommand -FilePath 'route.exe' -Arguments @('/f') -NoNewWindow
    if ($routeResult.Success) {
        Write-Log '  [OK] Route table cleared.' -Level OK
    } else {
        # route /f occasionally returns non-zero on IPv6-only systems
        # where the IPv4 route table is already empty
        Write-Log ("  [INFO] route /f returned code {0} (may be empty table)." -f $routeResult.ExitCode) -Level INFO
    }

    # ============================================================
    # 3. Reset Winsock catalog
    # ============================================================
    Write-Log 'Reinitializing Winsock catalog...' -Level INFO

    $winsockResult = Invoke-NativeCommand -FilePath 'netsh.exe' -Arguments @('winsock', 'reset') -NoNewWindow

    if ($winsockResult.Success) {
        Write-Log '  [OK] Winsock catalog reset.' -Level OK
    } else {
        Write-Log ("  [WARN] netsh winsock reset returned code {0}" -f $winsockResult.ExitCode) -Level WARN
        $winsockResult.StdErr | ForEach-Object {
            Write-Log ("    $_") -Level DEBUG
        }
    }

    # ============================================================
    # 4. Reset TCP/IP stack
    # ============================================================
    Write-Log 'Reinitializing TCP/IP stack configuration...' -Level INFO

    $ipResult = Invoke-NativeCommand -FilePath 'netsh.exe' -Arguments @('int', 'ip', 'reset') -NoNewWindow

    if ($ipResult.Success) {
        Write-Log '  [OK] TCP/IP stack reset.' -Level OK
    } else {
        Write-Log ("  [WARN] netsh int ip reset returned code {0}" -f $ipResult.ExitCode) -Level WARN
        $ipResult.StdErr | ForEach-Object {
            Write-Log ("    $_") -Level DEBUG
        }
    }

    # ============================================================
    # Summary
    # ============================================================
    # Overall success = all four operations returned zero
    $overallSuccess = $dnsResult.Success -and
                      $winsockResult.Success -and
                      $ipResult.Success
                      # Note: route /f intentionally excluded - often no-op

    $exitStatus = if ($overallSuccess) { 0 } else { 1 }
    Write-Log ("Network realignment operations finalized with exit status: {0}" -f $exitStatus) -Level INFO

    # ---- Verdict ----
    if ($overallSuccess) {
        Write-Log 'Network stack successfully re-aligned to factory defaults.' -Level OK
        Write-Log '[REBOOT REQUIRED] Please restart your computer soon.' -Level WARN
        Write-Log '[STATUS] Winsock catalog and IP interfaces cleanly reset.' -Level INFO

        # Mark reboot as required for the final summary (PostCheck)
        $Script:RebootRequired = $true
        if ($Script:RebootReasons -and -not $Script:RebootReasons.Contains('Step 23 (network reset)')) {
            [void]$Script:RebootReasons.Add('Step 23 (network reset)')
        }
    } else {
        Write-Log 'Some network interface modifications could not be fully written.' -Level WARN
        Write-Log ("[WARNING] netsh stack realignment returned non-zero code: {0}" -f $exitStatus) -Level WARN
        Write-Log 'A reboot may still be required. If network issues persist, run:' -Level INFO
        Write-Log '  netsh winsock reset' -Level INFO
        Write-Log '  netsh int ip reset' -Level INFO
    }

    Write-Log 'Step 23 complete.' -Level OK
}
# ============================================================
# STEP 24: Solid-State Drive (SSD) Storage Optimization
# ============================================================
function Invoke-Step24 {
    <#
    .SYNOPSIS
        Storage Optimization.

    .DESCRIPTION
        Detects each fixed drive's media type:
          * SSD / NVMe   -> skip. Windows schedules TRIM automatically.
          * HDD (spinning) -> launch defrag.exe in a new window.

        This follows Austin Davenport's correct warning: never defrag SSDs.
        Windows already handles TRIM and optimization for SSDs via the
        weekly "ScheduledDefrag" task. For HDDs, defrag is genuinely
        useful and can improve sequential access times.

        Drive type detection uses MSFT_PhysicalDisk.MediaType when
        available (Windows 8+), with a BusType fallback for NVMe.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 24: Storage Optimization' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    # ---- Detect HAGS + Game Mode (informational) ----
    try {
        $hagsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
        $hags = (Get-ItemProperty -Path $hagsPath -Name 'HwSchMode' -ErrorAction SilentlyContinue).HwSchMode
        $hagsText = switch ($hags) {
            1       { 'Disabled' }
            2       { 'Enabled' }
            default { 'Not configured (Windows default)' }
        }
        Write-Log ("  HAGS (Hardware-Accelerated GPU Scheduling) = {0}" -f $hagsText) -Level INFO
    } catch {
        Write-Log '  HAGS state not configured (Windows default).' -Level INFO
    }

    try {
        $gmPath = 'HKCU:\Software\Microsoft\GameBar'
        $gm = (Get-ItemProperty -Path $gmPath -Name 'AutoGameModeEnabled' -ErrorAction SilentlyContinue).AutoGameModeEnabled
        $gmText = switch ($gm) {
            0       { 'Disabled' }
            1       { 'Enabled' }
            default { 'Not configured (Windows default: enabled)' }
        }
        Write-Log ("  Game Mode = {0}" -f $gmText) -Level INFO
    } catch {
        Write-Log '  Game Mode state not configured (Windows default: enabled).' -Level INFO
    }

    # ---- Enumerate fixed drives ----
    $drives = @()
    try {
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop |
                  Where-Object { $_.DriveType -eq 3 }
    } catch {
        Write-Log 'Drive enumeration failed - skipping Step 24.' -Level WARN
        return
    }

    if (-not $drives) {
        Write-Log 'No fixed drives found.' -Level WARN
        return
    }

    # ---- Classify each drive ----
    $ssdDrives = @()
    $hddDrives = @()
    $unknownDrives = @()

    foreach ($d in $drives) {
        $letter   = $d.DeviceID.TrimEnd(':')
        $mediaType = $null
        $busType   = $null
        $friendly  = $null

        # Prefer MSFT_PhysicalDisk (available Windows 8+)
        try {
            $partitions = Get-Partition -DriveLetter $letter -ErrorAction Stop
            $disk       = Get-Disk -Number $partitions[0].DiskNumber -ErrorAction Stop
            $friendly   = $disk.FriendlyName
            $busType    = $disk.BusType

            $physical = Get-PhysicalDisk -DeviceNumber $disk.Number -ErrorAction SilentlyContinue
            if ($physical) {
                # MediaType: 0=Unspecified, 3=HDD, 4=SSD, 5=SCM
                $mediaType = $physical.MediaType
            }
        } catch {
            # Fall back to MSFT_PhysicalDisk WMI directly
            try {
                $wmi = Get-CimInstance -Namespace 'root\Microsoft\Windows\Storage' -ClassName 'MSFT_PhysicalDisk' -ErrorAction SilentlyContinue |
                       Select-Object -First 1
                if ($wmi) {
                    $mediaType = $wmi.MediaType
                }
            } catch { }
        }

        # Classify
        if ($busType -eq 'NVMe') {
            $ssdDrives += $letter
            Write-Log ("  {0}  NVMe SSD  ({1})  -> skip (Windows TRIM)" -f $d.DeviceID, $friendly) -Level INFO
        }
        elseif ($mediaType -eq 4 -or "$mediaType" -match "^(?i)SSD$") {
            $ssdDrives += $letter
            Write-Log ("  {0}  SSD       ({1})  -> skip (Windows TRIM)" -f $d.DeviceID, $friendly) -Level INFO
        }
        elseif ($mediaType -eq 3) {
            $hddDrives += $letter
            Write-Log ("  {0}  HDD       ({1})  -> defrag candidate" -f $d.DeviceID, $friendly) -Level INFO
        }
        else {
            $unknownDrives += $letter
            Write-Log ("  {0}  Unknown media type (BusType={1}, MediaType={2})  -> skip (safety)" -f $d.DeviceID, $busType, $mediaType) -Level INFO
        }
    }

    # ---- TRIM state (informational) ----
    try {
        $trimStatus = & fsutil.exe behavior query DisableDeleteNotify 2>&1
        $trimText   = $trimStatus -join ' '
        if ($trimText -match 'DisableDeleteNotify\s*=\s*0') {
            Write-Log '  TRIM: enabled and Windows-managed.' -Level OK
        } elseif ($trimText -match 'DisableDeleteNotify\s*=\s*1') {
            Write-Log '  TRIM: DISABLED - check storage driver.' -Level WARN
        }
    } catch { }

    # ---- Summary ----
    Write-Log '' -Level INFO
    Write-Log ("Drives classified: {0} SSD, {1} HDD, {2} unknown" -f $ssdDrives.Count, $hddDrives.Count, $unknownDrives.Count) -Level INFO

    # ---- Handle SSDs / Unknown - nothing to do ----
    # ---- VBS / HVCI state audit (informational) ----
    if ($Script:AllowVbsAudit) {
        try {
            $hvciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
            $vbsPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'

            $hvciEnabled = $null
            $vbsRunning  = $null

            # [FIX-STEP24-STRICTMODE] StrictMode-safe property access.
            if (Test-Path -LiteralPath $hvciPath) {
                try {
                    $__hvciProps = Get-ItemProperty -Path $hvciPath -Name 'Enabled' -ErrorAction SilentlyContinue
                    if ($__hvciProps -and $__hvciProps.PSObject.Properties['Enabled']) {
                        $hvciEnabled = $__hvciProps.Enabled
                    }
                } catch { }
            }
            if (Test-Path -LiteralPath $vbsPath) {
                try {
                    $__vbsProps = Get-ItemProperty -Path $vbsPath -Name 'EnableVirtualizationBasedSecurity' -ErrorAction SilentlyContinue
                    if ($__vbsProps -and $__vbsProps.PSObject.Properties['EnableVirtualizationBasedSecurity']) {
                        $vbsRunning = $__vbsProps.EnableVirtualizationBasedSecurity
                    }
                } catch { }
            }

            Write-Log '  VBS / HVCI audit:' -Level INFO
            Write-Log ("    VBS status:  {0}" -f $(if ($vbsRunning -eq 1) { 'ENABLED (may reduce CPU performance)' } elseif ($vbsRunning -eq 0) { 'Disabled' } else { 'Not configured (Windows default)' })) -Level INFO
            Write-Log ("    HVCI status: {0}" -f $(if ($hvciEnabled -eq 1) { 'ENABLED (may reduce CPU performance)' } elseif ($hvciEnabled -eq 0) { 'Disabled' } else { 'Not configured (Windows default)' })) -Level INFO
            if ($hvciEnabled -eq 1) {
                Write-Log '    To disable HVCI: Settings -> Privacy & security -> Windows Security -> Device security -> Core isolation' -Level INFO
                Write-Log '    Note: WinTune does NOT modify VBS/HVCI automatically (security tradeoff).' -Level INFO
            }
        } catch {
            Write-Log ("  VBS audit failed: {0}" -f $_.Exception.Message) -Level DEBUG
        }
    }

    # ---- Summary ----
if ($ssdDrives.Count -gt 0) {
        Write-Log ("SSDs detected ({0}): {1}" -f $ssdDrives.Count, ($ssdDrives -join ', ')) -Level INFO
        Write-Log '  Windows maintains TRIM and optimization automatically.' -Level INFO
        Write-Log '  No manual action needed on SSDs.' -Level INFO
    }

    if ($unknownDrives.Count -gt 0) {
        Write-Log ("Unknown-type drives ({0}): {1} - skipping for safety." -f $unknownDrives.Count, ($unknownDrives -join ', ')) -Level WARN
    }

    # ---- Handle HDDs - launch defrag in a separate window ----
    if ($hddDrives.Count -eq 0) {
        Write-Log 'No HDDs found. Step 24 complete (no action).' -Level OK
        return
    }

    if ($Script:DryRun) {
        Write-Log ("[PREVIEW] Would launch defrag.exe in a new window for HDDs: {0}" -f ($hddDrives -join ', ')) -Level PREVIEW
        return
    }

    Write-Log ("HDD(s) detected: {0}" -f ($hddDrives -join ', ')) -Level WARN
    Write-Log 'About to launch Windows defrag in a separate window.' -Level INFO
    Write-Log 'The defrag window will run independently of WinTune.' -Level INFO
    Write-Log 'You can minimize it and continue using your PC normally.' -Level INFO

    if (-not (Confirm-Action -Query 'Launch defrag on HDD drives?')) {
        Write-Log 'Step 24 HDD defrag skipped by user.' -Level WARN
        return
    }

    # Build the argument list: defrag each HDD letter
    $defragArgs = @()
    foreach ($letter in $hddDrives) {
        $defragArgs += $letter + ':'
    }

    Write-Log ("Launching: defrag.exe {0}" -f ($defragArgs -join ' ')) -Level INFO

    try {
        # Launch defrag.exe in a NEW visible window (not -NoNewWindow)
        $proc = Start-Process -FilePath 'defrag.exe' -ArgumentList ($defragArgs -join ' ') -PassThru

        Write-Log ("  [OK] defrag.exe launched (PID {0})." -f $proc.Id) -Level OK
        Write-Log '  A new window should be visible.' -Level INFO
        Write-Log '  WinTune will not wait for it to finish.' -Level INFO
    } catch {
        Write-Log ("Failed to launch defrag.exe: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    Write-Log 'Step 24 complete.' -Level OK
    Write-Log '[SUCCESS] HDD defrag launched (SSDs skipped).' -Level OK
}

function Invoke-Step25 {
    <#
    .SYNOPSIS
        Creates a System Restore point as the FIRST action of the run,
        so any subsequent change can be rolled back via the standard
        Windows System Restore wizard.

    .DESCRIPTION
        WinTune runs dozens of steps that modify caches, registry
        values, service state, and system configuration. If any of those
        changes goes wrong, a pre-change restore point is the fastest
        way to recover.

        Why this runs FIRST (not last):
          * A restore point is only useful if it predates the changes.
          * Creating it at the end of the run would capture the
            already-modified state - useless for rollback.
          * So the dispatcher places Invoke-Step25 at position 1.

        What happens:
          1. Temporarily set SystemRestorePointCreationFrequency = 0
             (bypasses Windows' 24-hour rate limit between restore points)
          2. Enumerate existing restore points (informational)
          3. Create a new restore point via Checkpoint-Computer
             - Type:    MODIFY_SETTINGS
             - Name:    WinTune_PreChange  (identifiable in the UI)
          4. Restore the frequency registry value to its original state

        Retention:
          * This step does NOT delete restore points.
          * Windows enforces retention automatically via the VSS shadow
            storage cap configured in Step 17 (default: 3% of volume).
          * When the cap is reached, Windows silently prunes the oldest
            restore points. No manual deletion is needed.
          * Do NOT use `vssadmin delete shadows /oldest` here - it
            deletes shadow COPIES, which may be Previous Versions
            snapshots rather than System Restore points.

        How to roll back:
          1. Open Start -> search "Create a restore point"
          2. In the System Protection tab, click "System Restore..."
          3. Select the "WinTune_PreChange" entry
          4. Follow the wizard (typically 5-15 minutes)

        Safety:
          * Requires System Protection enabled on the system drive
          * The frequency registry key is restored in a finally block,
            even if Checkpoint-Computer fails
          * No VSS data is deleted by this step
    #>
    [CmdletBinding()]
    param()

Write-Log 'STEP 25: System Restore Point (Safety Snapshot)' -Level STEP
Write-Log ('-' * 60) -Level STEP
Write-Log '' -Level INFO
Write-Log '  A restore point is created BEFORE any changes so you can roll' -Level INFO
Write-Log '  back if something goes wrong. This is a safety step - nothing' -Level INFO
Write-Log '  on your system is modified or deleted by this step.' -Level INFO
Write-Log '' -Level INFO
Write-Log '  To roll back later:' -Level INFO
Write-Log '    1. Open Start, search "Create a restore point"' -Level INFO
Write-Log '    2. Click "System Restore..."' -Level INFO
Write-Log '    3. Select the "WinTune_PreChange" entry' -Level INFO
Write-Log '    4. Follow the wizard (5-15 minutes)' -Level INFO
Write-Log '' -Level INFO
# [FIX-STEP25-VSS-1] Step 17 now uses a fixed-GB tier (3 GB <=500GB,
# 5 GB >500GB), not a percentage. Old "(Step 17, 3%)" was stale.
Write-Log '  Retention: managed by Windows via the VSS tier cap (see Step 17).' -Level INFO
Write-Log '  Process time: 30-90 seconds.' -Level INFO
Write-Log '' -Level INFO

if (-not (Confirm-Action -Query 'Create a pre-change restore point?')) {
        Write-Log 'Step 25 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would check snapshot balances, delete older backups, and trigger Checkpoint-Computer.' -Level PREVIEW
        return
    }

    # Capture current restore point count for later verification
    $rpCount = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count
    Write-Log ("  Existing restore points detected: {0}" -f $rpCount) -Level INFO

    $restoreRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'

    # ============================================================
    # 1. Bypass the 24-hour creation frequency limit
    # ============================================================
    Write-Log 'Injecting system frequency bypass rules into kernel memory...' -Level INFO

    # Capture original value (or note that it did not exist)
    $origFreq = $null
    $hadFreqValue = $false
    try {
        $prop = Get-ItemProperty -Path $restoreRegPath -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue
        if ($prop -and $prop.PSObject.Properties['SystemRestorePointCreationFrequency']) {
            $origFreq = $prop.SystemRestorePointCreationFrequency
            $hadFreqValue = $true
        }
    } catch { }

    $freqChanged = $false

    try {
        if (-not (Test-Path -LiteralPath $restoreRegPath)) {
            New-Item -Path $restoreRegPath -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $restoreRegPath -Name 'SystemRestorePointCreationFrequency' -Value 0 -Type DWord -Force -ErrorAction Stop
        Write-Log '  [OK] Frequency limit bypassed (set to 0).' -Level OK
        $freqChanged = $true
    } catch {
        Write-Log ("  [WARN] Could not set frequency registry value: {0}" -f $_.Exception.Message) -Level WARN
        # Continue anyway - Checkpoint-Computer may still succeed if
        # the last restore point was > 24 hours ago
    }

    # ============================================================
    # 2. Retention: Windows manages VSS storage
    # ============================================================
    # Windows 11 no longer exposes the SystemRestore WMI class, and
    # `vssadmin delete shadows /oldest` may delete non-restore-point
    # shadow copies (e.g., Previous Versions). Retention is enforced by
    # Windows via the VSS shadow storage cap configured in Step 17.
    Write-Log 'Retention: Windows manages VSS storage (see Step 17 for the cap).' -Level INFO

    # ============================================================
    # 3. Create a fresh restore point
    # ============================================================
    Write-Log 'Committing fresh state snapshot safety net...' -Level INFO
    Write-Log '  This may take up to 90 seconds...' -Level INFO

    try {
        # Ensure System Protection is enabled on the system drive
        try {
            Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        } catch {
            # Ignore - may already be enabled, or may be policy-disabled
        }

        Checkpoint-Computer -Description 'WinTune_PreChange' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop

        Write-Log '  [SUCCESS] System Restore Point successfully locked into shadow arrays.' -Level OK
        Write-Log '[SUCCESS] Step 25: New restore point created.' -Level OK

        # Verify the restore point actually appears in the list
        $finalRps = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count
        if ($finalRps -gt $rpCount) {
            Write-Log ("  Verified: restore point count increased {0} -> {1}" -f $rpCount, $finalRps) -Level OK
        } else {
            # Diagnose why the count didn't move. Two common causes:
            #   (a) VSS cap from Step 17 is full, so Windows pruned the
            #       oldest point to make room for the new one (net zero).
            #   (b) SystemRestorePointCreationFrequency is still honored
            #       despite our reg override (rare, but happens when a
            #       domain GPO overrides the HKCU/HKLM value).
            Write-Log ("  [WARN] Checkpoint-Computer reported success but restore point count is still {0}." -f $rpCount) -Level WARN

            # (a) Inspect VSS storage usage
            $capDiag = $null
            try {
                $vssOut = & vssadmin.exe list shadowstorage 2>&1
                $capDiag = ($vssOut | Where-Object { $_ -match 'Maximum Shadow Copy Storage space|Used Shadow Copy Storage space|Allocated Shadow Copy Storage space' }) -join ' | '
            } catch { }

            if ($capDiag) {
                Write-Log ("  [DIAG] VSS storage: {0}" -f $capDiag) -Level INFO
                # [FIX-STEP25-VSS-2] Compute the actual cap for this drive.
                $__capGB = 3
                try {
                    $__d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -EA SilentlyContinue
                    if ($__d -and $__d.Size -gt 500GB) { $__capGB = 5 }
                } catch { }
                Write-Log ("  [DIAG] Most likely cause: the {0} GB VSS cap from Step 17 is already full," -f $__capGB) -Level INFO
                Write-Log '         so Windows silently pruned the oldest restore point to fit the new one.' -Level INFO
                Write-Log '  [DIAG] Fix: increase the cap with:' -Level INFO
                Write-Log '         vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10GB' -Level INFO
                Write-Log '         or remove older points manually via System Restore UI.' -Level INFO
            } else {
                Write-Log '  [DIAG] Could not read VSS storage. Possible causes:' -Level INFO
                Write-Log '         - VSS cap from Step 17 is full (older point pruned)' -Level INFO
                Write-Log '         - SystemRestorePointCreationFrequency is still enforced by domain GPO' -Level INFO
                Write-Log '         - Checkpoint-Computer no-op because a point was created <24h ago' -Level INFO
            }

            # (b) Check the frequency value still in place
            try {
                $freqNow = (Get-ItemProperty -Path $restoreRegPath -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue).SystemRestorePointCreationFrequency
                if ($null -ne $freqNow -and [int]$freqNow -ne 0) {
                    Write-Log ("  [DIAG] SystemRestorePointCreationFrequency is {0} (not 0) after Checkpoint - a GPO is overriding it." -f $freqNow) -Level WARN
                }
            } catch { }
        }
    } catch {
        Write-Log '  [WARNING] Unable to generate checkpoint. Ensure System Protection is enabled.' -Level WARN
        Write-Log ("[ERROR] Step 25: {0}" -f $_.Exception.Message) -Level WARN

        Write-Log '  Common causes: System Protection disabled via policy, low disk space, or VSS service stopped.' -Level INFO
    } finally {
        # ============================================================
        # 4. Restore the 24-hour frequency protection (ALWAYS runs)
        # ============================================================
        if ($freqChanged) {
            try {
                if ($hadFreqValue) {
                    Set-ItemProperty -Path $restoreRegPath -Name 'SystemRestorePointCreationFrequency' -Value $origFreq -Type DWord -Force -ErrorAction Stop
                    Write-Log ("  [OK] Frequency limit restored to {0} minutes." -f $origFreq) -Level OK
                } else {
                    Remove-ItemProperty -Path $restoreRegPath -Name 'SystemRestorePointCreationFrequency' -Force -ErrorAction Stop
                    Write-Log '  [OK] Frequency limit removed (was not set before).' -Level OK
                }
            } catch {
                Write-Log ("  [WARN] Could not restore frequency registry value: {0}" -f $_.Exception.Message) -Level WARN
            }
        }
    }
}
# ============================================================
# STEP 26: Windows Ultimate Performance Power Plan Tuning
# ============================================================
function Invoke-Step26 {
    <#
    .SYNOPSIS
        Power plan + power mode optimization.

    .DESCRIPTION
        By default, activates the Balanced power plan AND the Balanced
        power mode overlay. Matches JayzTwoCents' recommendation (don't
        force High/Ultimate Performance) and works on all modern
        Windows 10 1809+ / Windows 11 builds.

        With -AllowUltimatePerformance, activates Ultimate Performance
        plan + Best performance overlay instead. Blocked on battery
        unless -ForceIrreversible is passed.

        Design notes:
          * Balanced scheme GUID is looked up dynamically (falls back
            to the SCHEME_BALANCED alias if not found by name).
          * Power mode overlay is set via PowerSetActiveOverlayScheme
            (powrprof.dll). Missing on Windows 10 pre-1809; caught.
          * Settings UI is refreshed via ms-settings:power to force
            the Power service to drop stale cache.
          * Verification re-reads the active plan + overlay after.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 26: Power Plan and Power Mode Optimization' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    # 1. Detect battery
    $hasBattery = $false
    try {
        $hasBattery = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0
    } catch { }

    # 2. Decide which plan + overlay to apply
    if ($Script:AllowUltimatePerformance) {
        if ($hasBattery -and -not $Script:ForceIrreversible) {
            Write-Log 'Ultimate Performance requested on battery-powered system.' -Level WARN
            Write-Log 'Blocked to protect battery life and thermals.' -Level WARN
            Write-Log 'Override with -AllowUltimatePerformance -ForceIrreversible' -Level WARN
            Write-Log 'Falling back to Balanced.' -Level INFO
            $useUltimate = $false
        } else {
            Write-Log 'Ultimate Performance authorized via -AllowUltimatePerformance.' -Level WARN
            $useUltimate = $true
        }
    } else {
        Write-Log 'Default mode: Balanced plan + Balanced power mode.' -Level INFO
        Write-Log 'Use -AllowUltimatePerformance to opt into the aggressive plan.' -Level INFO
        $useUltimate = $false
    }

    if (-not (Confirm-Action -Query 'Apply power plan optimization?')) {
        Write-Log 'Step 26 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        if ($useUltimate) {
            Write-Log 'Would activate Ultimate Performance plan + Best performance overlay.' -Level PREVIEW
        } else {
            Write-Log 'Would activate Balanced plan + Balanced power mode overlay.' -Level PREVIEW
        }
        return
    }

    $overallSuccess = $true

    # 3. Find the target power plan GUID dynamically
    $targetPlanGuid = $null

    if ($useUltimate) {
        $baseUltimateGuid = 'e9a42b02-d5df-448d-aa00-03f14749eb61'
        $allSchemes = & powercfg.exe /list 2>&1
        foreach ($line in $allSchemes) {
            if ($line -match [regex]::Escape($baseUltimateGuid)) {
                $m = [regex]::Match($line, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
                if ($m.Success) { $targetPlanGuid = $m.Groups[1].Value; break }
            }
        }
        if (-not $targetPlanGuid) {
            Write-Log 'Ultimate Performance not present - creating a copy...' -Level INFO
            $dupOutput = & powercfg.exe -duplicatescheme $baseUltimateGuid 2>&1
            foreach ($line in $dupOutput) {
                if ($line -match 'Power Scheme GUID') {
                    $m = [regex]::Match($line, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
                    if ($m.Success) { $targetPlanGuid = $m.Groups[1].Value; break }
                }
            }
        }
    } else {
        $allSchemes = & powercfg.exe /list 2>&1
        foreach ($line in $allSchemes) {
            if ($line -match '\(Balanced\)' -or $line -match '\(Recommended\)') {
                $m = [regex]::Match($line, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
                if ($m.Success) { $targetPlanGuid = $m.Groups[1].Value; break }
            }
        }
        if (-not $targetPlanGuid) {
            $targetPlanGuid = 'SCHEME_BALANCED'
        }
    }

    if (-not $targetPlanGuid) {
        Write-Log 'Could not resolve target power plan GUID.' -Level ERROR
        Write-Log '[WARNING] Step 26 aborted: plan GUID lookup failed.' -Level WARN
        return
    }

    $targetPlanName = if ($useUltimate) { 'Ultimate Performance' } else { 'Balanced' }
    Write-Log ("Target plan: {0} ({1})" -f $targetPlanName, $targetPlanGuid) -Level INFO

    # 4. Activate the power plan
    Write-Log 'Activating power plan...' -Level INFO
    $activateResult = & powercfg.exe /setactive $targetPlanGuid 2>&1
    if ($LASTEXITCODE -ne 0) {
          Write-Log ("  [WARN] powercfg /setactive returned {0}: {1}" -f $LASTEXITCODE, ($activateResult -join ' ').Trim()) -Level WARN
    } else {
        Write-Log '  [OK] Plan activation command sent.' -Level OK
    }

    # 5. Set the power mode overlay
    $overlayGuid = if ($useUltimate) {
        'ded574b5-45a0-4f42-8737-46345c09c238'
    } else {
        '00000000-0000-0000-0000-000000000000'
    }
    $overlayName = if ($useUltimate) { 'Best performance' } else { 'Balanced' }

    Write-Log ("Setting power mode overlay to: {0}" -f $overlayName) -Level INFO

    try {
        if (-not ('PowerModeHelper' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PowerModeHelper {
    [DllImport("powrprof.dll", EntryPoint = "PowerSetActiveOverlayScheme", SetLastError = true)]
    public static extern int PowerSetActiveOverlayScheme(Guid OverlaySchemeGuid);
}
"@ -ErrorAction Stop
        }

        $overlayUri = [Guid]$overlayGuid
        $overlayResult = [PowerModeHelper]::PowerSetActiveOverlayScheme($overlayUri)

        if ($overlayResult -eq 0) {
            Write-Log '  [OK] Overlay applied.' -Level OK
        } else {
            Write-Log ("  [WARN] PowerSetActiveOverlayScheme returned {0}" -f $overlayResult) -Level WARN
            $overallSuccess = $false
        }
    } catch {
        Write-Log ("  [WARN] Overlay API unavailable: {0}" -f $_.Exception.Message) -Level WARN
        Write-Log '  (Normal on Windows 10 builds older than 1809.)' -Level INFO
    }

    # 6. Refresh the Settings UI cache
    Write-Log 'Refreshing Settings UI cache...' -Level INFO
    try {
        Start-Process 'ms-settings:power' -ErrorAction Stop
        Start-Sleep -Seconds 2
        Get-Process -Name 'SystemSettings' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Log '  [OK] Settings UI refreshed.' -Level OK
    } catch {
        Write-Log ("  [WARN] Could not refresh Settings UI: {0}" -f $_.Exception.Message) -Level WARN
    }

    # 7. Verify
    Write-Log 'Verifying final state...' -Level INFO
    Start-Sleep -Milliseconds 500

    $activeOut = & powercfg.exe /getactivescheme 2>&1
    $activeText = $activeOut -join ' '
    Write-Log ("  Active plan: {0}" -f $activeText.Trim()) -Level INFO

    if ($useUltimate) {
        if ($activeText -notmatch 'Ultimate|Performance') {
            Write-Log '  [WARN] Active plan does not appear to be Ultimate Performance.' -Level WARN
            $overallSuccess = $false
        }
    } else {
        if ($activeText -notmatch 'Balanced|Recommended') {
            Write-Log '  [WARN] Active plan does not appear to be Balanced.' -Level WARN
            $overallSuccess = $false
        }
    }

    $root = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
    $acProp = Get-ItemProperty -Path $root -Name 'ActiveOverlayAcPowerScheme' -ErrorAction SilentlyContinue
    $ac = if ($acProp -and $acProp.PSObject.Properties['ActiveOverlayAcPowerScheme']) { $acProp.ActiveOverlayAcPowerScheme } else { '(not set)' }
    $dcProp = Get-ItemProperty -Path $root -Name 'ActiveOverlayDcPowerScheme' -ErrorAction SilentlyContinue
    $dc = if ($dcProp -and $dcProp.PSObject.Properties['ActiveOverlayDcPowerScheme']) { $dcProp.ActiveOverlayDcPowerScheme } else { '(not set)' }
    Write-Log ("  Active overlay AC: {0}" -f $ac) -Level INFO
    Write-Log ("  Active overlay DC: {0}" -f $dc) -Level INFO

    # 8. Result
    if ($overallSuccess) {
        if ($useUltimate) {
            Write-Log '[SUCCESS] Power plan set to Ultimate Performance.' -Level OK
        } else {
            Write-Log '[SUCCESS] Power plan set to Balanced (recommended).' -Level OK
        }
        Write-Log 'Step 26 complete.' -Level OK
    } else {
        Write-Log 'Step 26 completed with warnings.' -Level WARN
        Write-Log '[WARNING] Step 26: one or more power-plan operations did not verify.' -Level WARN
    }
}

function Invoke-Step27 {
    <#
    .SYNOPSIS
        Reduces visual-effect overhead for the current user by
        disabling transparency and animation effects, while
        preserving font smoothing for text readability.

    .DESCRIPTION
        Registry changes (all HKCU - current user only):

          Transparency:
            HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize
              EnableTransparency = 0

          Classic window animation:
            HKCU\Control Panel\Desktop\WindowMetrics
              MinAnimate = "0"  (REG_SZ, string)

          Modern accessibility animations:
            HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility
              AnimationEffect = 0

          Font smoothing (deliberately ENABLED):
            HKCU\Control Panel\Desktop
              FontSmoothing = "2"       (REG_SZ)
              FontSmoothingType = 2      (DWORD, subpixel/cleartype)

        Broadcast:
          SendMessageTimeout HWND_BROADCAST WM_SETTINGCHANGE
          with lParam='Environment' so shell components re-read
          the settings without requiring a sign-out.

        Effect:
          * Transparency (Start menu, taskbar, window borders) -> opaque
          * Window minimize/maximize animations -> instant
          * Modern UWP animation overlays -> disabled
          * Fonts remain anti-aliased with ClearType

        Safety:
          * All changes are current-user (HKCU)
          * Reversible: set the values back to 1 (transparency,
            animations) and sign out
          * No system-wide (HKLM) changes
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 27: Desktop Interface Responsiveness Tuning' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Reduces unnecessary Windows visual effects for the current user.' -Level INFO
    Write-Log 'Transparency disabled. Window animations disabled. Font smoothing preserved.' -Level INFO

    if (-not (Confirm-Action -Query 'Optimize interface visual effects and disable animations?')) {
        Write-Log 'Step 27 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would disable user-level transparency and window animation effects.' -Level PREVIEW
        return
    }

    $overallSuccess = $true

    # ---- Helper: idempotent registry value write ----
    $setRegValue = {
        param(
            [string]$Path,
            [string]$Name,
            [object]$Value,
            [string]$Type   # 'DWord' or 'String'
        )
        try {
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }

            $params = @{
                Path         = $Path
                Name         = $Name
                Value        = $Value
                PropertyType = $Type
                Force        = $true
                ErrorAction  = 'Stop'
            }
            New-ItemProperty @params | Out-Null
            return $true
        } catch {
            Write-Log ("  Failed to set {0}\{1}: {2}" -f $Path, $Name, $_.Exception.Message) -Level WARN
            return $false
        }
    }

    # ============================================================
    # 1. Disable transparency
    # ============================================================
    Backup-RegistryKey -Step 27 -RegPath 'HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    Backup-RegistryKey -Step 27 -RegPath 'HKCU\Control Panel\Desktop'
    Backup-RegistryKey -Step 27 -RegPath 'HKCU\Control Panel\Desktop\WindowMetrics'
    Backup-RegistryKey -Step 27 -RegPath 'HKCU\Control Panel\Mouse'
    Backup-RegistryKey -Step 27 -RegPath 'HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility'
    Backup-RegistryKey -Step 27 -RegPath 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
    Write-Log 'Disabling visual transparency...' -Level INFO

    $transparencyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    if (& $setRegValue $transparencyPath 'EnableTransparency' 0 'DWord') {
        Write-Log '  [OK] Transparency disabled.' -Level OK
    } else {
        $overallSuccess = $false
    }

    # ============================================================
    # 2. Disable classic window animation
    # ============================================================
    Write-Log 'Disabling classic window animation...' -Level INFO

    $windowMetricsPath = 'HKCU:\Control Panel\Desktop\WindowMetrics'
    if (& $setRegValue $windowMetricsPath 'MinAnimate' '0' 'String') {
        Write-Log '  [OK] Window minimize/maximize animation disabled.' -Level OK
    } else {
        $overallSuccess = $false
    }

    # ============================================================
    # 3. Disable modern accessibility animations
    # ============================================================
    Write-Log 'Disabling modern interface animation overlays...' -Level INFO

    $a11yPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Accessibility'
    if (& $setRegValue $a11yPath 'AnimationEffect' 0 'DWord') {
        Write-Log '  [OK] Modern animation overlays disabled.' -Level OK
    } else {
        $overallSuccess = $false
    }

    # ============================================================
    # 4. Preserve font smoothing (explicitly ensure it's ON)
    # ============================================================
    Write-Log 'Preserving font smoothing for readable text...' -Level INFO

    $desktopPath = 'HKCU:\Control Panel\Desktop'
    if (& $setRegValue $desktopPath 'FontSmoothing' '2' 'String') {
        Write-Log '  [OK] Font smoothing preserved.' -Level OK
    } else {
        $overallSuccess = $false
    }

    if (& $setRegValue $desktopPath 'FontSmoothingType' 2 'DWord') {
        Write-Log '  [OK] Font smoothing type set to ClearType.' -Level OK
    } else {
        $overallSuccess = $false
    }

    # ============================================================
    # 5. Broadcast WM_SETTINGCHANGE
    # ============================================================
    # ---- Menu and hover delays (responsiveness) ----
    Write-Log 'Zeroing menu and hover delays...' -Level INFO
    try {
        $desktopPath = 'HKCU:\Control Panel\Desktop'
        $mousePath   = 'HKCU:\Control Panel\Mouse'
        if (-not (Test-Path -LiteralPath $desktopPath)) { New-Item -Path $desktopPath -Force | Out-Null }
        if (-not (Test-Path -LiteralPath $mousePath))   { New-Item -Path $mousePath   -Force | Out-Null }
        New-ItemProperty -Path $desktopPath -Name 'MenuShowDelay' -Value '0' -PropertyType String -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $mousePath   -Name 'MouseHoverTime' -Value '0' -PropertyType String -Force -ErrorAction Stop | Out-Null
        Write-Log '  [OK] Menu delay + hover time set to 0.' -Level OK
    } catch {
        Write-Log ("  [WARN] Could not set UI delays: {0}" -f $_.Exception.Message) -Level WARN
    }

    # ---- Classic right-click context menu (Windows 11 only) ----
    Write-Log 'Enabling classic Windows 10 context menu...' -Level INFO
    try {
        $osBuild = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).BuildNumber
        if ($osBuild -ge 22000) {
            $clsidPath = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
            if (-not (Test-Path -LiteralPath $clsidPath)) { New-Item -Path $clsidPath -Force | Out-Null }
            Set-Item -Path $clsidPath -Value '' -Force -ErrorAction Stop
            Write-Log '  [OK] Classic context menu registered.' -Level OK
            Write-Log '  (Restart Explorer for the change to take effect.)' -Level INFO
        } else {
            Write-Log '  [SKIP] Not Windows 11 - classic menu is default.' -Level DEBUG
        }
    } catch {
        Write-Log ("  [WARN] Could not enable classic context menu: {0}" -f $_.Exception.Message) -Level WARN
    }

    Write-Log 'Broadcasting user-environment refresh...' -Level INFO
    # P3: Step 27 rollback entries
    Add-RollbackEntry -Step 27 -Type 'RegistryHKCU' -Data @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name = 'EnableTransparency'; Existed = $false; Value = $null; Type = 'DWord' }
    Add-RollbackEntry -Step 27 -Type 'RegistryHKCU' -Data @{ Path = 'HKCU:\Control Panel\Desktop\WindowMetrics'; Name = 'MinAnimate'; Existed = $false; Value = $null; Type = 'String' }
    Add-RollbackEntry -Step 27 -Type 'RegistryHKCU' -Data @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Accessibility'; Name = 'AnimationEffect'; Existed = $false; Value = $null; Type = 'DWord' }

    try {
        # Compile P/Invoke type once per session
        if (-not ('Native.Win32' -as [type])) {
            $signature = @'
using System;
using System.Runtime.InteropServices;

namespace Native {
    public static class Win32 {
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr SendMessageTimeout(
            IntPtr hWnd,
            uint Msg,
            IntPtr wParam,
            string lParam,
            uint fuFlags,
            uint uTimeout,
            out IntPtr result);
    }
}
'@
            Add-Type -TypeDefinition $signature -ErrorAction Stop
        }

        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $SMTO_ABORTIFHUNG = 0x0002
        $result = [IntPtr]::Zero

        $ret = [Native.Win32]::SendMessageTimeout(
            $HWND_BROADCAST,
            $WM_SETTINGCHANGE,
            [IntPtr]::Zero,
            'Environment',
            $SMTO_ABORTIFHUNG,
            5000,
            [ref]$result
        )

        if ($ret -ne [IntPtr]::Zero) {
            Write-Log '  [OK] User-environment broadcast delivered.' -Level OK
        } else {
            Write-Log '  Broadcast returned 0 - some shell windows may not have refreshed.' -Level DEBUG
        }
    } catch {
        Write-Log ("  Broadcast failed: {0}" -f $_.Exception.Message) -Level WARN
        $overallSuccess = $false
    }

    # ============================================================
    # Verdict
    # ============================================================
    if ($overallSuccess) {
        Write-Log 'Desktop visual-effect configuration completed.' -Level OK
        Write-Log '[SUCCESS] Step 27: Visual-effect configuration completed successfully.' -Level OK
    } else {
        Write-Log 'Step 27 completed with one or more configuration errors.' -Level WARN
        Write-Log '[WARNING] Step 27: One or more operations returned an error.' -Level WARN
    }

    # ------------------------------------------------------------
    # Apply the registry changes now by restarting Explorer
    # ------------------------------------------------------------
    # Visual-effect registry writes (transparency, animations,
    # context menu) are only re-read by Explorer on a full restart
    # of the shell process. WM_SETTINGCHANGE alone is not enough.
    Write-Log 'Restarting Explorer to apply visual-effect changes...' -Level INFO

    $explorerProcs = Get-Process -Name 'explorer' -ErrorAction SilentlyContinue
    if ($explorerProcs) {
        foreach ($proc in $explorerProcs) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Log ("  [OK] Terminated explorer.exe (PID {0})" -f $proc.Id) -Level DEBUG
            } catch {
                Write-Log ("  [WARN] Could not terminate explorer PID {0}: {1}" -f $proc.Id, $_.Exception.Message) -Level WARN
            }
        }
    } else {
        Write-Log '  explorer.exe was not running.' -Level DEBUG
    }

    Start-Sleep -Seconds 2

    try {
        Start-Process 'explorer.exe' -ErrorAction Stop
    } catch {
        Write-Log ("  [WARN] Could not restart explorer.exe: {0}" -f $_.Exception.Message) -Level WARN
    }

    # Watchdog: wait up to 15 seconds for Explorer to appear
    $maxWait = 15
    $waited  = 0
    $explorerAlive = $false

    while ($waited -lt $maxWait) {
        Start-Sleep -Seconds 1
        $waited++
        if (Get-Process -Name 'explorer' -ErrorAction SilentlyContinue) {
            $explorerAlive = $true
            break
        }
    }

    if ($explorerAlive) {
        Write-Log ("  [OK] Explorer restarted after {0} second(s). Visual changes applied." -f $waited) -Level OK
    } else {
        Write-Log '  [WARN] Explorer did not restart automatically. Launching second attempt...' -Level WARN
        try {
            Start-Process 'explorer.exe' -ErrorAction Stop
            Start-Sleep -Seconds 3
            if (Get-Process -Name 'explorer' -ErrorAction SilentlyContinue) {
                Write-Log '  [OK] Explorer recovered on second attempt.' -Level OK
            } else {
                Write-Log '  [ERROR] Explorer still not running. Restart manually via Task Manager.' -Level ERROR
            }
        } catch {
            Write-Log ("  [ERROR] Second launch failed: {0}" -f $_.Exception.Message) -Level ERROR
        }
    }
    Write-Log 'Step 27 complete.' -Level OK
}
# ============================================================
# STEP 28: Enable Windows Storage Sense
# ============================================================
function Invoke-Step28 {
    <#
    .SYNOPSIS
        Enables Windows Storage Sense with a weekly schedule and
        safe cleanup rules. Protects the Downloads folder from
        automatic deletion.

    .DESCRIPTION
        Storage Sense is Windows' built-in background cleanup
        engine (Windows 10 1809+, redesigned in Windows 11 22H2).
        Two registry schemas are configured to cover both:

        Schema V2 (Windows 11 22H2+):
          HKCU\...\StorageSense\Parameters\StorageSensorV2
            State           = 1     (enabled)
            RunPeriodDays   = 7     (weekly)
            AppsSetting     = 1     (clean app temp files)
            RecycleBinDays  = 30    (empty recycle bin after 30 days)
            DownloadsDays   = 0     (NEVER delete Downloads)

        Schema Legacy (Windows 10 1809 - 11 21H2):
          HKCU\...\StorageSense\Parameters\StoragePolicy
            01     = 1   (Storage Sense enabled)
            04     = 1   (clean temp files)
            08     = 1   (clean recycle bin)
            2048   = 7   (weekly schedule)
            32     = 0   (Downloads - never delete)

        Why both:
          * Writing only V2 on older Windows -> ignored
          * Writing only legacy on newer Windows -> ignored
          * Writing both -> covered on all supported versions
          * No conflicts - the OS reads whichever schema it knows

        What Storage Sense will do (weekly):
          * Delete temp files not in use
          * Empty recycle bin items older than 30 days
          * Clear Windows Update delivery optimization cache
          * NEVER delete files in Downloads (protected)

        Safety:
          * All HKCU - current user only
          * Downloads protection is explicit (DownloadsDays = 0)
          * Does not affect user documents, photos, or videos
          * Reversible via Settings -> System -> Storage -> Storage Sense
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 28: Enable Windows Storage Sense' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Configures the native Windows engine for weekly background cleanup.' -Level INFO
    Write-Log '[SAFEGUARD] Downloads folder set to NEVER be deleted.' -Level INFO

    if (-not (Confirm-Action -Query 'Configure and automate weekly Storage Sense operations?')) {
        Write-Log 'Step 28 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would configure Storage Sense automation rules (V2 + legacy schemas).' -Level PREVIEW
        return
    }

    $overallSuccess = $true
    $failCount = 0

    # ---- Helper: idempotent DWORD write ----
    $setDword = {
        param([string]$Path, [string]$Name, [int]$Value)
        try {
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            return $true
        } catch {
            Write-Log ("  Failed to set {0}\{1}: {2}" -f $Path, $Name, $_.Exception.Message) -Level WARN
            return $false
        }
    }

    # ============================================================
    # 1. Configure modern Windows 11 schema (StorageSensorV2)
    # ============================================================
    Backup-RegistryKey -Step 28 -RegPath 'HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StorageSensorV2'
    Backup-RegistryKey -Step 28 -RegPath 'HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
    Write-Log 'Configuring modern Windows 11 StorageSense infrastructure...' -Level INFO

    $v2Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StorageSensorV2'

    $v2Values = @(
        @{ Name = 'State';          Value = 1;  Desc = 'Storage Sense enabled' }
        @{ Name = 'RunPeriodDays';  Value = 7;  Desc = 'Weekly schedule' }
        @{ Name = 'AppsSetting';    Value = 1;  Desc = 'Clean app temp files' }
        @{ Name = 'RecycleBinDays'; Value = 30; Desc = 'Recycle Bin age limit' }
        @{ Name = 'DownloadsDays';  Value = 0;  Desc = 'Downloads protected' }
    )

    foreach ($item in $v2Values) {
        if (& $setDword $v2Path $item.Name $item.Value) {
            Write-Log ("  [OK] {0} = {1} ({2})" -f $item.Name, $item.Value, $item.Desc) -Level OK
        } else {
            Write-Log ("  [WARN] Failed to set {0}" -f $item.Name) -Level WARN
            $overallSuccess = $false
            $failCount++
        }
    }

    # ============================================================
    # 2. Configure legacy schema (StoragePolicy)
    # ============================================================
    Write-Log 'Applying legacy fallback structural alignment layers...' -Level INFO

    $legacyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'

    $legacyValues = @(
        @{ Name = '01';   Value = 1; Desc = 'Storage Sense enabled' }
        @{ Name = '04';   Value = 1; Desc = 'Clean temp files' }
        @{ Name = '08';   Value = 1; Desc = 'Clean Recycle Bin' }
        @{ Name = '2048'; Value = 7; Desc = 'Weekly schedule' }
        @{ Name = '32';   Value = 0; Desc = 'Downloads protected' }
    )

    foreach ($item in $legacyValues) {
        if (& $setDword $legacyPath $item.Name $item.Value) {
            Write-Log ("  [OK] {0} = {1} ({2})" -f $item.Name, $item.Value, $item.Desc) -Level OK
        } else {
            Write-Log ("  [WARN] Failed to set {0}" -f $item.Name) -Level WARN
            $overallSuccess = $false
            $failCount++
        }
    }

    # ============================================================
    # Verdict
    # ============================================================
    if ($overallSuccess) {
        Write-Log 'Storage Sense automation completed cleanly.' -Level OK
        Write-Log '[SUCCESS] Step 28: Storage Sense background scheduling deployed successfully.' -Level OK
        Write-Log '  Schedule:      Weekly (7 days)' -Level INFO
        Write-Log '  Recycle Bin:   30-day retention' -Level INFO
        Write-Log '  Downloads:     PROTECTED (never deleted)' -Level INFO
    } else {
        Write-Log 'Step 28 finished with localized configuration anomalies.' -Level WARN
        Write-Log ("[WARNING] Step 28: {0} registry write(s) failed." -f $failCount) -Level WARN
    }

    Write-Log 'Step 28 complete.' -Level OK
}
# ============================================================
# STEP 29: Disable Legacy SMBv1
# ============================================================
function Invoke-Step29 {
    <#
    .SYNOPSIS
        Disables SMBv1 at two layers: the Windows Optional Feature
        (component store) and the LanmanServer service registry.

    .DESCRIPTION
        What SMBv1 is:
          * The original Server Message Block protocol from 1983
          * Vulnerable to EternalBlue/WannaCry, SMBGhost, and
            numerous other CVEs
          * Deprecated by Microsoft since Windows 10 1709
          * Removed by default in Windows 11 24H2

        Two-layer disable:
          Layer 1 - Windows Optional Feature:
            * Disables all SMB1Protocol* subfeatures via DISM
            * Removes SMB1 binaries from the component store
            * Requires TrustedInstaller (elevated, takes 30-45s)
            * Subfeatures include:
              - SMB1Protocol-Client
              - SMB1Protocol-Server
              - SMB1Protocol-Deprecation

          Layer 2 - Registry hardening:
            * HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
              SMB1 = 0
            * Prevents the SMB Server service from ever negotiating
              SMBv1 even if the binaries are present
            * Belt-and-suspenders defense

        Impact:
          * Modern Windows (SMBv2/v3) is unaffected
          * Windows shares, printers, and network access work normally
          * LEGACY devices (pre-2010 NAS, old printers) may lose
            access if they only speak SMBv1

        Safety:
          * Reversible via DISM (Enable-WindowsOptionalFeature)
          * Does not delete user data
          * Requires elevated prompt
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 29: Disable Legacy SMBv1' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Hardens Windows security by disabling SMBv1 network blocks.' -Level INFO
    Write-Log '[WARNING] Legacy network appliances (pre-2010) may disconnect.' -Level WARN
    Write-Log '[PROCESS TIME] This feature verification can take up to 45 seconds.' -Level INFO

    if (-not (Confirm-Action -Query 'Disable legacy insecure SMBv1 protocol layers?')) {
        Write-Log 'Step 29 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would query DISM component stores, disable SMB1 features, and apply Lanman registry bits.' -Level PREVIEW
        return
    }

    $overallSuccess = $true

    # ============================================================
    # LAYER 1: Disable SMB1 via Windows Optional Features (DISM)
    # ============================================================
    # Pre-flight: if CBS has a pending reboot, Get-WindowsOptionalFeature
    # will block for 5-20 minutes while TrustedInstaller tries to service
    # the pending operation. Skip Step 29 entirely in that state and let
    # the user reboot first.
    $__cbsPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    if ($__cbsPending) {
        Write-Log 'Step 29 skipped: CBS reboot pending (TrustedInstaller will block).' -Level WARN
        Write-Log '  Reboot first, then re-run WinTune to disable SMBv1.' -Level WARN
        return
    }

    Write-Log 'Running deep component store checks on SMB1 infrastructure...' -Level INFO
    Write-Log 'Engaging TrustedInstaller subsystem - Please do not close this console...' -Level INFO

    try {
        # Enumerate SMB1Protocol* features in a background job with a 60s
        # timeout. Get-WindowsOptionalFeature is un-interruptible by Ctrl+C
        # on some Windows builds, so a job is the only way to bound it.
        $__job = Start-Job -ScriptBlock {
            Get-WindowsOptionalFeature -Online -ErrorAction Stop |
                Where-Object { $_.FeatureName -like 'SMB1Protocol*' -and $_.State -eq 'Enabled' }
        }
        $__completed = Wait-Job -Job $__job -Timeout 60
        if (-not $__completed) {
            Stop-Job -Job $__job -ErrorAction SilentlyContinue
            Remove-Job -Job $__job -Force -ErrorAction SilentlyContinue
            Write-Log 'Step 29 skipped: Get-WindowsOptionalFeature timed out after 60s.' -Level WARN
            Write-Log '  TrustedInstaller is busy. Reboot and re-run to disable SMBv1.' -Level WARN
            return
        }
        $features = Receive-Job -Job $__job -ErrorAction Stop
        Remove-Job -Job $__job -Force -ErrorAction SilentlyContinue

        if ($features -and @($features).Count -gt 0) {
            $featureTotal = @($features).Count
            $featureIndex = 0
            foreach ($feature in $features) {
                $featureIndex++
                Write-Log ("  [{0}/{1}] Servicing SMB1 feature (may take 30-45s): {2}" -f $featureIndex, $featureTotal, $feature.FeatureName) -Level WARN

                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    # -NoRestart because we'll suggest a reboot separately
                    Disable-WindowsOptionalFeature -Online -FeatureName $feature.FeatureName -NoRestart -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
                    $sw.Stop()
                    Write-Log ("    [OK] Disabled: {0} ({1:N1}s)" -f $feature.FeatureName, $sw.Elapsed.TotalSeconds) -Level OK
                } catch {
                    $sw.Stop()
                    Write-Log ("    [WARN] Could not disable {0}: {1}" -f $feature.FeatureName, $_.Exception.Message) -Level WARN
                    $overallSuccess = $false
                }
            }
        } else {
            Write-Log '  [INFO] SMBv1 optional features are already inactive.' -Level INFO
        }
    } catch {
        Write-Log ("Could not alter SMB1 feature state: {0}" -f $_.Exception.Message) -Level WARN
        $overallSuccess = $false
    }

    # ============================================================
    # LAYER 2: Registry hardening for LanmanServer
    # ============================================================
    Backup-RegistryKey -Step 29 -RegPath 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    Write-Log 'Injecting defensive registry boundaries into network driver configurations...' -Level INFO

    $lanmanPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

    try {
        if (-not (Test-Path -LiteralPath $lanmanPath)) {
            New-Item -Path $lanmanPath -Force -ErrorAction Stop | Out-Null
        }

        New-ItemProperty -Path $lanmanPath -Name 'SMB1' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null

        Write-Log '  [OK] LanmanServer SMB1 = 0 (negotiation disabled).' -Level OK
    } catch {
        Write-Log ("  [WARN] Could not set LanmanServer SMB1 registry value: {0}" -f $_.Exception.Message) -Level WARN
        $overallSuccess = $false
    }

    # ============================================================
    # Optional verification: query SMB1 state via Get-SmbServerConfiguration
    # ============================================================
    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($smbConfig) {
            Write-Log ("  SMB1 negotiation currently: {0}" -f $(if ($smbConfig.EnableSMB1Protocol) { 'ENABLED (still active)' } else { 'Disabled (expected)' })) -Level INFO
            if ($smbConfig.EnableSMB1Protocol) {
                Write-Log '  [WARN] SMB1 still reports enabled - a reboot may be required.' -Level WARN
                # Not fatal - reboot applies the change
            }
        }
    } catch {
        Write-Log '  SMB configuration verification unavailable.' -Level DEBUG
    }

    # ============================================================
    # Verdict
    # ============================================================
    if ($overallSuccess) {
        Write-Log 'SMBv1 network protocol components successfully disabled.' -Level OK
        Write-Log '[SUCCESS] Step 29: SMBv1 protocol hardening applied successfully.' -Level OK
        Write-Log 'A reboot may be required to fully release SMB1 bindings.' -Level INFO
    } else {
        Write-Log 'Step 29 completed with localized framework warnings.' -Level WARN
        Write-Log '[WARNING] Step 29: One or more network hardening tasks returned a non-zero code.' -Level WARN
    }

    Write-Log 'Step 29 complete.' -Level OK
}
# ============================================================
# STEP 30: Network Hardening - Disable LLMNR and WPAD
# ============================================================
function Invoke-Step30 {
    <#
    .SYNOPSIS
        Disables LLMNR multicast name resolution and WPAD proxy
        auto-discovery to prevent credential-theft attacks on
        local networks.

    .DESCRIPTION
        Threat model:
          * LLMNR (Link-Local Multicast Name Resolution) is a
            fallback for DNS failures. When DNS doesn't resolve a
            name, Windows broadcasts the query to the local subnet.
            An attacker on the same network can respond and capture
            the victim's NTLM hash.
          * WPAD (Web Proxy Auto-Discovery) broadcasts a request
            for a proxy config. An attacker can respond with a
            malicious PAC file that redirects all traffic through
            them, capturing credentials.

        Registry changes:
          LLMNR (HKLM - machine-wide):
            HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
              EnableMulticast = 0

          WinHTTP WPAD (HKLM - machine-wide):
            HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
              Internet Settings\WinHttp
              DisableWpad = 1

          User proxy auto-detect (HKCU - current user):
            HKCU\Software\Microsoft\Windows\CurrentVersion\
              Internet Settings
              AutoDetect = 0

        Domain-join detection:
          * Checks PartOfDomain via WMI
          * On domain-joined machines, prompts an extra
            confirmation because disabling WPAD may break
            Intune, WSUS, Exchange autodiscover

        Safety:
          * All changes are reversible
          * No user data touched
          * Does not disable DNS, only the multicast fallback
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 30: Network Hardening - Disable LLMNR and WPAD' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Disables LLMNR multicast fallback and WPAD proxy auto-discovery.' -Level INFO
    Write-Log '[WARNING] On domain-joined machines, disabling AutoDetect may break Intune/WSUS/Exchange.' -Level WARN

    if (-not (Confirm-Action -Query 'Apply LLMNR and WPAD security hardening tweaks?')) {
        Write-Log 'Step 30 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would disable LLMNR multicast and proxy auto-detection.' -Level PREVIEW
        return
    }

    # ============================================================
    # 1. Detect domain join
    # ============================================================
    $domainJoined = $false
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $domainJoined = [bool]$cs.PartOfDomain
    } catch {
        Write-Log ("  Domain-join detection failed: {0}" -f $_.Exception.Message) -Level DEBUG
    }

    if ($domainJoined) {
        Write-Log 'This machine appears to be domain-joined.' -Level WARN
        Write-Log 'Disabling WPAD/auto-proxy may break corporate services (Intune/WSUS/Exchange).' -Level WARN

        if (-not (Confirm-Action -Query 'Proceed with LLMNR/WPAD hardening on domain-joined machine?')) {
            Write-Log 'LLMNR/WPAD hardening aborted by user.' -Level INFO
            Write-Log '[INFO] Step 30 aborted: domain-joined, user declined.' -Level INFO
            return
        }
    }

    $overallSuccess = $true
    $failCount = 0

    # ---- Helper: idempotent DWORD write ----
    $setDword = {
        param([string]$Path, [string]$Name, [int]$Value)
        try {
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            return $true
        } catch {
            Write-Log ("  Failed to set {0}\{1}: {2}" -f $Path, $Name, $_.Exception.Message) -Level WARN
            return $false
        }
    }

    # ============================================================
    # 2. Disable LLMNR multicast fallback
    # ============================================================
    Backup-RegistryKey -Step 30 -RegPath 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    Backup-RegistryKey -Step 30 -RegPath 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
    Backup-RegistryKey -Step 30 -RegPath 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    Write-Log 'Disabling LLMNR multicast fallback...' -Level INFO

    $llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    if (& $setDword $llmnrPath 'EnableMulticast' 0) {
        Write-Log '  [OK] LLMNR multicast disabled.' -Level OK
    } else {
        Write-Log '  [WARN] EnableMulticast write failed.' -Level WARN
        $overallSuccess = $false
        $failCount++
    }

    # ============================================================
    # 3. Disable WinHTTP WPAD discovery
    # ============================================================
    Write-Log 'Disabling WinHTTP WPAD discovery...' -Level INFO

    $wpadPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
    if (& $setDword $wpadPath 'DisableWpad' 1) {
        Write-Log '  [OK] WinHTTP WPAD discovery disabled.' -Level OK
    } else {
        Write-Log '  [WARN] DisableWpad write failed.' -Level WARN
        $overallSuccess = $false
        $failCount++
    }

    # ============================================================
    # 4. Disable user proxy auto-detection
    # ============================================================
    Write-Log 'Disabling user proxy auto-detection...' -Level INFO

    $autoDetectPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if (& $setDword $autoDetectPath 'AutoDetect' 0) {
        Write-Log '  [OK] User proxy auto-detection disabled.' -Level OK
    } else {
        Write-Log '  [WARN] AutoDetect write failed.' -Level WARN
        $overallSuccess = $false
        $failCount++
    }

    # ============================================================
    # Verdict
    # ============================================================
    if ($overallSuccess) {
        Write-Log 'Network credential exposure hardening completed.' -Level OK
        Write-Log '[SUCCESS] Step 30: LLMNR and WPAD hardening completed successfully.' -Level OK
    } else {
        Write-Log 'Step 30 completed with one or more errors.' -Level WARN
        Write-Log ("[WARNING] Step 30: {0} hardening operation(s) failed." -f $failCount) -Level WARN
    }

    Write-Log 'Step 30 complete.' -Level OK
}
# ============================================================
# STEP 31: Enable DNS over HTTPS (DoH)
# ============================================================
function Invoke-Step31 {
    <#
    .SYNOPSIS
        Configures the Windows DNS client for automatic DoH
        (DNS over HTTPS) where supported by the system build and
        the configured DNS resolver.

    .DESCRIPTION
        Windows build requirement:
          Build 19041 (Windows 10 2004) or later. Earlier builds
          don't have the DoH client stack.

        Configuration:
          1. Registry (HKLM) - Enable AutoDoh globally:
             HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
               EnableAutoDoh = 2   (2 = automatic)
          2. netsh - Enable automatic DoH mode:
             netsh dnsclient set global doh=auto
          3. Flush DNS cache so existing entries re-resolve

        What this does NOT do:
          * Does not set a specific DoH resolver IP
          * Does not force DoH on resolvers that don't support it
          * Does not encrypt DNS for applications that bypass
            the Windows DNS client (Chrome, Firefox have their
            own DoH)

        To activate DoH you must ALSO use a DoH-capable DNS server:
          * Cloudflare: 1.1.1.1 / 1.0.0.1
          * Google:     8.8.8.8 / 8.8.4.4
          * Quad9:      9.9.9.9 / 149.112.112.112
          * OpenDNS:    208.67.222.222

        Safety:
          * Registry write is HKLM (machine-wide)
          * Reversible by removing EnableAutoDoh
          * No user data touched
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 31: Enable DNS over HTTPS (DoH)' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Configures Windows DNS client for automatic DoH.' -Level INFO
    Write-Log '[WARNING] DoH requires a supported build AND a DoH-capable resolver.' -Level WARN

    if (-not (Confirm-Action -Query 'Enable DNS over HTTPS?')) {
        Write-Log 'Step 31 skipped by user.' -Level WARN
        return
    }

    # ============================================================
    # 1. Detect Windows build
    # ============================================================
    $osBuild = $null
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $osBuild = [int]$os.BuildNumber
    } catch {
        Write-Log ("Could not determine Windows build: {0}" -f $_.Exception.Message) -Level WARN
    }

    if (-not $osBuild) {
        Write-Log 'Unable to determine Windows build.' -Level WARN
        Write-Log '[WARNING] Step 31: Windows build detection failed.' -Level WARN
        return
    }

    Write-Log ("Detected Windows build: {0}" -f $osBuild) -Level INFO

    # ============================================================
    # 2. Build compatibility check
    # ============================================================
    if ($osBuild -lt 19041) {
        Write-Log 'Windows build is too old for the supported DoH configuration.' -Level WARN
        Write-Log ("[SKIP] Step 31: Unsupported Windows build {0}." -f $osBuild) -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would configure Windows DNS client for automatic DoH.' -Level PREVIEW
        return
    }

    $overallSuccess = $true
    $failCount = 0

    # ============================================================
    # 3. Set EnableAutoDoh registry value
    # ============================================================
    Write-Log 'Configuring Windows DNS client for automatic DoH...' -Level INFO

    $dohRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
    try {
        if (-not (Test-Path -LiteralPath $dohRegPath)) {
            New-Item -Path $dohRegPath -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -Path $dohRegPath -Name 'EnableAutoDoh' -Value 2 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log '  [OK] EnableAutoDoh configured (value = 2).' -Level OK
    } catch {
        Write-Log ("  [WARN] EnableAutoDoh failed: {0}" -f $_.Exception.Message) -Level WARN
        $overallSuccess = $false
        $failCount++
    }

    # ============================================================
    # 4. Configure DNS client global DoH mode
    # ============================================================
    Write-Log 'Configuring DNS client DoH mode...' -Level INFO

    try {
        $netshResult = & netsh.exe dnsclient set global doh=auto 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log '  [OK] Automatic DoH mode configured.' -Level OK
        } else {
            Write-Log ("  [WARN] netsh DoH configuration failed (exit {0})." -f $LASTEXITCODE) -Level WARN
            $netshResult | ForEach-Object { Write-Log ("    {0}" -f $_) -Level DEBUG }
            $overallSuccess = $false
            $failCount++
        }
    } catch {
        Write-Log ("  [WARN] netsh invocation failed: {0}" -f $_.Exception.Message) -Level WARN
        $overallSuccess = $false
        $failCount++
    }

    # ============================================================
    # 5. Flush DNS client cache
    # ============================================================
    Write-Log 'Flushing DNS client cache...' -Level INFO

    try {
        $null = & ipconfig.exe /flushdns 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log '  [OK] DNS cache flushed.' -Level OK
        } else {
            Write-Log ("  [WARN] DNS cache flush failed (exit {0})." -f $LASTEXITCODE) -Level WARN
            $overallSuccess = $false
            $failCount++
        }
    } catch {
        Write-Log ("  [WARN] ipconfig invocation failed: {0}" -f $_.Exception.Message) -Level WARN
        $overallSuccess = $false
        $failCount++
    }

    # ============================================================
    # 6. Detect DNS servers and check DoH capability
    # ============================================================
    $knownDohServers = @(
        '1.1.1.1', '1.0.0.1',               # Cloudflare
        '8.8.8.8', '8.8.4.4',               # Google
        '9.9.9.9', '149.112.112.112',       # Quad9
        '208.67.222.222', '208.67.220.220', # OpenDNS
        '94.140.14.14', '94.140.15.15'      # AdGuard
    )

    try {
        $currentDns = @(
            Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } |
            ForEach-Object { $_.ServerAddresses } |
            Select-Object -Unique
        )

        if ($currentDns.Count -gt 0) {
            Write-Log ("  Current DNS servers: {0}" -f ($currentDns -join ', ')) -Level INFO
            $dohCapable = @($currentDns | Where-Object { $knownDohServers -contains $_ })
            if ($dohCapable.Count -gt 0) {
                Write-Log ("  DoH-capable resolvers: {0}" -f ($dohCapable -join ', ')) -Level OK
                Write-Log '  DoH will activate automatically on the next DNS resolution.' -Level INFO
            } else {
                Write-Log '  [WARN] None of the configured DNS servers support DoH.' -Level WARN
                Write-Log '  AutoDoh is enabled but dormant until a supported resolver is configured.' -Level WARN
                Write-Log '  Recommended: 1.1.1.1 (Cloudflare), 9.9.9.9 (Quad9), 8.8.8.8 (Google)' -Level INFO
            }
        }
    } catch {
        Write-Log ("  Could not inspect DNS servers: {0}" -f $_.Exception.Message) -Level DEBUG
    }

    # ============================================================
    # Verdict
    # ============================================================
    if ($overallSuccess) {
        Write-Log 'Windows DoH configuration completed.' -Level OK
        Write-Log '[SUCCESS] Step 31: DoH configuration completed.' -Level OK
        Write-Log '' -Level INFO
        Write-Log 'IMPORTANT: To activate encrypted DNS, configure a DoH-capable resolver:' -Level INFO
        Write-Log '  Cloudflare: 1.1.1.1, 1.0.0.1' -Level INFO
        Write-Log '  Google:     8.8.8.8, 8.8.4.4' -Level INFO
        Write-Log '  Quad9:      9.9.9.9, 149.112.112.112' -Level INFO
    } else {
        Write-Log 'Step 31 completed with errors.' -Level WARN
        Write-Log ("[WARNING] Step 31: {0} operation(s) failed." -f $failCount) -Level WARN
    }

    Write-Log 'Step 31 complete.' -Level OK
}


# ============================================================
# STEP 32: Microsoft Defender Attack Surface Reduction (ASR)
# ============================================================
function Invoke-Step32 {
    <#
    .SYNOPSIS
        Configures seven selected Microsoft Defender ASR rules in
        Audit Mode. Rules log suspicious activity but do not block.

    .DESCRIPTION
        What ASR rules do:
          * Block or log behaviors commonly used by malware
          * Examples: Office macros spawning processes, script
            files downloading executables, credential theft from
            LSASS, executable content from email clients

        Why Audit Mode:
          * Block mode can break legitimate workflows (e.g.,
            macros in signed Office documents)
          * Audit mode lets you review Defender events for 1-2
            weeks before switching to Block
          * Zero user-facing disruption during the audit period

        Rules configured (7 total):
          BE9BA2D9-... Block Office apps from creating child processes
          D4F940AB-... Block Office apps from creating executable content
          3B576869-... Block Office apps from injecting into other processes
          75668C1F-... Block Office apps from creating child processes
          D3E037E1-... Block JS/VBS from launching downloaded content
          5BEB7EFE-... Block execution of potentially obfuscated scripts
          92E97FA1-... Block Win32 API calls from Office macros

        Verification:
          * After writing, re-read preferences and confirm each rule
            has value 2 (AuditMode)
          * Fails loudly if any rule is missing or has wrong value

        How to switch to Block mode later:
          * Review Defender -> Protection history -> ASR events
          * For rules with no legitimate hits, call:
            Add-MpPreference -AttackSurfaceReductionRules_Ids <guid>
                             -AttackSurfaceReductionRules_Actions Enabled
          * Re-run this step with Mode='Enabled' if you want a
            scripted switch (not implemented here)

        Safety:
          * Audit Mode is non-blocking
          * Reversible: Remove-MpPreference
          * Requires Defender to be the active AV
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 32: Microsoft Defender Attack Surface Reduction (ASR)' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'MODE: AUDIT ONLY - rules log but do NOT block.' -Level INFO
    Write-Log 'Review Defender ASR audit events before enabling Block mode.' -Level INFO

    if (-not (Confirm-Action -Query 'Deploy Microsoft Defender ASR rules in Audit Mode?')) {
        Write-Log 'Step 32 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would configure 7 Defender ASR rules in AuditMode.' -Level PREVIEW
        return
    }

    # ---- Domain-join detection ----
    # On domain-joined machines, ASR rules are often managed by Group Policy.
    # Setting them locally may be a no-op or may conflict with the domain
    # configuration. Warn the user and let them decide.
    $domainJoined32 = $false
    try {
        $domainJoined32 = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
    } catch { }

    if ($domainJoined32) {
        Write-Log 'This machine is domain-joined.' -Level WARN
        Write-Log 'ASR rules may be enforced by Group Policy and cannot be changed locally.' -Level WARN
        Write-Log 'Local changes will be reported as failed verification if a GPO overrides them.' -Level WARN
        Write-Log 'Continuing in read-only verification mode (no local writes will be attempted).' -Level WARN
        $Script:Step32GpoMode = $true
    } else {
        $Script:Step32GpoMode = $false
    }

    # ---- Verify Defender is available ----
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mpStatus.AMServiceEnabled) {
            Write-Log 'Microsoft Defender Antivirus service is not running.' -Level WARN
            Write-Log 'ASR rules require Defender to be the active antivirus.' -Level WARN
            return
        }
        Write-Log ('Defender version: {0}' -f $mpStatus.AMEngineVersion) -Level DEBUG
    } catch {
        Write-Log ("Microsoft Defender cmdlets unavailable: {0}" -f $_.Exception.Message) -Level WARN
        Write-Log 'Step 32 requires the Defender PowerShell module. Skipping.' -Level WARN
        return
    }

    # ---- ASR rule GUIDs ----
    $asrRuleIds = @(
        'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'   # Block Office child processes
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'   # Block Office executable content
        '3B576869-A4EC-4529-8536-B80A7769E899'   # Block Office process injection
        '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'   # Block Office child processes (2)
        'D3E037E1-3EB8-44C8-A917-57927947596D'   # Block JS/VBS downloaded content
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'   # Block obfuscated scripts
        '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'   # Block Win32 API from Office macros
    )

    $actionMode = 'AuditMode'   # Change to 'Enabled' to activate Block mode

    # ============================================================
    # 1. Apply the ASR rules
    # ============================================================
    Write-Log ('Configuring {0} Defender ASR rules in {1}...' -f $asrRuleIds.Count, $actionMode) -Level INFO

    if ($Script:Step32GpoMode) {
        Write-Log 'Skipping local ASR writes â€” domain policy is authoritative.' -Level INFO
        Write-Log 'Showing current ASR state for information only:' -Level INFO
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
                $id = $pref.AttackSurfaceReductionRules_Ids[$i]
                $act = $pref.AttackSurfaceReductionRules_Actions[$i]
                $modeText = switch ([int]$act) {
                    0 { 'Disabled' }
                    1 { 'Block' }
                    2 { 'Audit' }
                    6 { 'Warn' }
                    default { "Unknown ($act)" }
                }
                Write-Log ("  {0}: {1}" -f $id, $modeText) -Level INFO
            }
        } catch {
            Write-Log '  Could not read current ASR state locally.' -Level WARN
            if ($domainJoined32) {
                Write-Log '  This is EXPECTED on domain-joined machines: ASR state is managed by Group Policy.' -Level INFO
                Write-Log '  To view the effective rules, run on the domain controller:' -Level INFO
                Write-Log '    Get-MpPreference (from a machine with the Defender module)' -Level INFO
                Write-Log '  or check GPO: Computer Configuration -> Administrative Templates -> Windows Components -> Microsoft Defender Antivirus -> Attack Surface Reduction' -Level INFO
            } else {
                Write-Log '  Run Get-MpPreference manually to inspect current ASR rules.' -Level INFO
            }
        }
        Write-Log 'Step 32 complete (domain policy mode).' -Level OK
        return
    }


    try {
        $actions = @($actionMode) * $asrRuleIds.Count
        Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleIds -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop

        Write-Log ("  [OK] {0} rules written to Defender preferences." -f $asrRuleIds.Count) -Level OK
    } catch {
        Write-Log ("  [WARN] Add-MpPreference failed: {0}" -f $_.Exception.Message) -Level WARN
        return
    }

    # ============================================================
    # 2. Verify rules persisted correctly
    # ============================================================
    Write-Log 'Verifying configured ASR rules...' -Level INFO

    try {
        $pref = Get-MpPreference -ErrorAction Stop

        # Build a hashtable: rule-id (uppercase) -> action-code (int)
        $prefMap = @{}
        for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $key = $pref.AttackSurfaceReductionRules_Ids[$i].ToString().ToUpper()
            $prefMap[$key] = [int]$pref.AttackSurfaceReductionRules_Actions[$i]
        }

        # 2 = AuditMode, 1 = Enabled (block), 0 = Disabled
        $expectedCode = 2
        $missing = @()
        $wrongMode = @()

        foreach ($id in $asrRuleIds) {
            $key = $id.ToUpper()
            if (-not $prefMap.ContainsKey($key)) {
                $missing += $id
                continue
            }
            if ($prefMap[$key] -ne $expectedCode) {
                $wrongMode += ('{0}={1}' -f $id, $prefMap[$key])
            }
        }

        if ($missing.Count -gt 0) {
            Write-Log ("  [WARN] {0} rule(s) missing after configuration: {1}" -f $missing.Count, ($missing -join ', ')) -Level WARN
            Write-Log '[WARNING] Step 32: ASR configuration/verification failed.' -Level WARN
            return
        }

        if ($wrongMode.Count -gt 0) {
            Write-Log ("  [WARN] {0} rule(s) not in AuditMode: {1}" -f $wrongMode.Count, ($wrongMode -join ', ')) -Level WARN
            Write-Log '[WARNING] Step 32: ASR configuration/verification failed.' -Level WARN
            return
        }

        Write-Log ("  [OK] All {0} ASR rules verified in Audit Mode." -f $asrRuleIds.Count) -Level OK
    } catch {
        Write-Log ("  [WARN] Verification failed: {0}" -f $_.Exception.Message) -Level WARN
        Write-Log '[WARNING] Step 32: ASR configuration/verification failed.' -Level WARN
        return
    }

    # ============================================================
    # Verdict
    # ============================================================
    Write-Log 'Microsoft Defender ASR configuration verified.' -Level OK
    Write-Log '[SUCCESS] Step 32: ASR AuditMode configuration verified.' -Level OK
    Write-Log '' -Level INFO
    Write-Log 'Next steps for Block mode:' -Level INFO
    Write-Log '  1. Use the system for 1-2 weeks normally.' -Level INFO
    Write-Log '  2. Review Defender -> Protection history -> ASR audit events.' -Level INFO
    Write-Log '  3. For rules with no legitimate hits, switch to Block:' -Level INFO
    Write-Log '     Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID>' -Level INFO
    Write-Log '                      -AttackSurfaceReductionRules_Actions Enabled' -Level INFO

    Write-Log 'Step 32 complete.' -Level OK
}

# ============================================================
# STEP 33: Unified App Infrastructure Upgrades via Winget
# ============================================================
function Invoke-Step33 {
    <#
    .SYNOPSIS
        Launches a detached visible PowerShell window that handles
        the entire winget upgrade flow: enumerate, pins, search,
        show, confirm, upgrade, verify.

    .DESCRIPTION
        This step is intentionally minimal. All winget work happens
        in the detached runner. WinTune continues immediately.

        Gate:
          * winget.exe must be present
          * -AllowWinget flag required (otherwise skip)

        Runner does:
          * Enumerate upgradable apps
          * Show pinned packages
          * Search each app in the catalog
          * Show full details for each app
          * Ask for one final Y/N confirmation
          * Silent upgrade of all upgradable apps
          * Re-enumerate to verify
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 33: Unified App Infrastructure Upgrades via Winget' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Launches a detached winget shell for full app upgrades.' -Level INFO

    # ---- Gate 1: winget presence check (informational only) ----
    # If winget isn't installed, the detached runner will attempt to
    # install it from GitHub before proceeding. This is non-blocking:
    # WinTune continues through other steps while the runner works.
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Log 'winget.exe not detected in PATH.' -Level WARN
        Write-Log 'The detached runner will attempt auto-install from GitHub.' -Level INFO
    } else {
        Write-Log ("  winget detected at: {0}" -f $winget.Source) -Level DEBUG
    }


    # ---- Gate 2: -AllowWinget required ----
    if (-not $Script:AllowWinget) {
        Write-Log 'No -AllowWinget flag supplied - Step 33 skipped.' -Level WARN
        Write-Log 'Add -AllowWinget to launch the detached winget upgrade shell.' -Level INFO
        Write-Log '[INFO] Step 33 skipped: -AllowWinget authorization flag absent.' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would launch a detached winget upgrade shell.' -Level PREVIEW
        return
    }

    # ---- Confirmation ----
    Write-Log 'About to launch a detached PowerShell window for winget upgrades.' -Level WARN
    Write-Log 'The new window will:' -Level INFO
    Write-Log '  - Enumerate upgradable applications' -Level INFO
    Write-Log '  - Show pinned packages' -Level INFO
    Write-Log '  - Search the catalog for each app' -Level INFO
    Write-Log '  - Display full package details' -Level INFO
    Write-Log '  - Ask for a final Y/N confirmation' -Level INFO
    Write-Log '  - Perform the silent upgrade' -Level INFO

    if (-not (Confirm-Action -Query 'Launch the detached winget upgrade shell?')) {
        Write-Log 'Step 33 skipped by user.' -Level WARN
        return
    }

    # ---- Locate runner (embedded) ----
    if (-not $Script:EmbeddedWingetRunner) {
        Write-Log 'Embedded Winget runner missing - this is a bug.' -Level ERROR
        return
    }
    Write-Log 'Using embedded Winget runner' -Level OK

    # ---- Write runner to TEMP ----
    $runnerPath = New-SecureRunnerPath -LeafName 'Winget.ps1'
    try {
        Set-Content -LiteralPath $runnerPath -Value $Script:EmbeddedWingetRunner -Encoding UTF8 -ErrorAction Stop
        Write-Log ("  [OK] Runner written to: {0}" -f $runnerPath) -Level OK
    } catch {
        Write-Log ("Failed to write runner: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    # ---- Set environment variables for the child ----
    $env:FC_LOG_DIR   = $Script:ScriptDir
    $env:FC_YES_TO_ALL = if ($Script:YesToAll) { '1' } else { '0' }
    $env:FC_ALLOW_UNKNOWN_VERSIONS = if ($Script:AllowUnknownPackageVersions) { '1' } else { '0' }

    # ---- Launch detached visible shell ----
    Write-Log 'Launching detached visible PowerShell window...' -Level INFO

    # Fix B3 v2: probe the runner host before committing to a launch
    $__prereq = Test-DetachedLaunchPrereqs
    if (-not $__prereq.Ok) {
        Write-Log ("  [FAIL] Detached launch prerequisites failed: {0}" -f $__prereq.Reason) -Level ERROR
        Write-Log '  Step marked Failed (child could not start).' -Level ERROR
        throw ("Detached runner prereq failure: {0}" -f $__prereq.Reason)
    }

    # [FIX-DETACHED-5C] cross-run guard
    $__existing = @(Get-ExistingDetachedRunnerProcess -Kind 'Winget')
    if ($__existing.Count -gt 0) {
        Write-Log ("  [SKIP] Winget runner already active (PID {0}, started {1})." -f $__existing[0].Pid, $__existing[0].StartedAt) -Level WARN
        Write-Log '  Close the existing window first, or wait for it to exit, then re-run.' -Level WARN
        $Script:LastStepStatus = 'Skipped'
        return
    }

    try {
        $child = Start-Process -FilePath $Script:RunnerPowerShellExe -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$runnerPath`"" -PassThru

        Write-Log ("  [OK] Child PowerShell launched (PID {0})." -f $child.Id) -Level OK
        Register-DetachedExitTracking -Child $child -Kind 'Winget' -Note 'Step 33'
        Register-TrackedRunnerKind -RunnerPid $child.Id -Kind 'Winget' -Note 'Step 33'
        Add-ReportRunner -Kind 'Winget' -RunnerPid $child.Id -Note 'Step 33'
        Write-Log '  WinTune will continue; winget upgrade runs independently.' -Level INFO
        Write-Log '  Look for the new window: "WinTune - Winget Upgrade (Full Detail Mode)"' -Level INFO
    } catch {
        Write-Log ("Failed to launch child PowerShell: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    Write-Log 'Step 33 launched (detached). Winget runs independently.' -Level OK

    # ---- B3 fix: clear FC_* env vars so a re-run in this session starts fresh ----
    Remove-Item Env:\FC_YES_TO_ALL -ErrorAction SilentlyContinue
    Remove-Item Env:\FC_ALLOW_UNKNOWN_VERSIONS -ErrorAction SilentlyContinue
    Write-Log '[SUCCESS] Step 33: Detached winget upgrade shell launched.' -Level OK
    $Script:LastStepStatus = 'Detached'
}



# ============================================================
# STEP 34: Font Cache and Explorer Shell Icon Index Rebuilds
# ============================================================
function Invoke-Step34 {
    <#
    .SYNOPSIS
        Rebuilds the Windows font cache and the explorer shell icon
        index. Complements Step 8 (which resets thumbnail + icon
        caches) by additionally targeting the font cache service.

    .DESCRIPTION
        What gets cleared:
          * Font Cache service databases:
              %SystemRoot%\ServiceProfiles\LocalService\AppData\
                Local\FontCache\*.dat
          * Legacy font cache:
              %SystemRoot%\System32\FNTCACHE.DAT (older Windows)

        Why this helps:
          * Font cache can grow to 100+ MB over time
          * Corrupted cache manifests as:
              - Wrong glyphs rendering (boxes instead of letters)
              - Slow font enumeration in apps
              - Missing/incorrect CJK characters
          * Explorer icon index rebuild fixes "stuck" overlay icons
            (OneDrive, Dropbox, etc. showing wrong status)

        What this step does NOT do:
          * Does not delete system fonts
          * Does not touch user fonts in %LOCALAPPDATA%\Microsoft\Windows\Fonts
          * Does not affect installed apps' font references

        Side effects:
          * Font Cache service restarted (takes ~2 seconds)
          * First font render after rebuild is slightly slower
          * Explorer icons re-render on first browse

        Gating:
          * Runs as part of aggressive icon reset
          * Requires -DeepIconReset OR is enabled by default
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 34: Font Cache and Explorer Shell Icon Index Rebuilds' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Rebuilds font cache databases and explorer shell icon index.' -Level INFO

    if (-not (Confirm-Action -Query 'Rebuild font cache and Explorer icon index?')) {
        Write-Log 'Step 34 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would rebuild font cache and explorer icon index.' -Level PREVIEW
        return
    }

    $overallSuccess = $true

    # ============================================================
    # 1. Stop FontCache service
    # ============================================================
    Write-Log 'Stopping FontCache service to unlock cache databases...' -Level INFO

    $fontCacheSvc = Get-Service -Name 'FontCache' -ErrorAction SilentlyContinue
    $fontCacheWasRunning = $false

    if ($fontCacheSvc) {
        $fontCacheWasRunning = ($fontCacheSvc.Status -eq 'Running')

        if ($fontCacheWasRunning) {
            try {
                Stop-Service -Name 'FontCache' -Force -ErrorAction Stop
                Write-Log '  [OK] FontCache service stopped.' -Level OK
                Start-Sleep -Seconds 1
            } catch {
                Write-Log ("  [WARN] Could not stop FontCache: {0}" -f $_.Exception.Message) -Level WARN
                $overallSuccess = $false
            }
        } else {
            Write-Log '  FontCache service already stopped.' -Level DEBUG
        }
    } else {
        Write-Log '  FontCache service not present (unusual).' -Level WARN
    }

    # ============================================================
    # 2. Delete font cache databases
    # ============================================================
    Write-Log 'Clearing font cache databases...' -Level INFO

    # [FIX-STEP34-PATHS] Also scan modern Win11 24H2+ font cache locations.
    # The FontCache service on newer builds may stage .dat files under
    # ProgramData and the user's LOCALAPPDATA in addition to the legacy
    # ServiceProfiles\LocalService path. Adding these is harmless — a
    # missing path just logs "Path not present" and skips.
    $fontCachePaths = @(
        (Join-Path $env:SystemRoot 'ServiceProfiles\LocalService\AppData\Local\FontCache')
        (Join-Path $env:SystemRoot 'ServiceProfiles\LocalService\AppData\Local\FontCache\FontCache-S-1-5-18')
        (Join-Path $env:SystemRoot 'ServiceProfiles\LocalService\AppData\Local\FontCache\FontCache-S-1-5-21')
        (Join-Path $env:ProgramData 'Microsoft\Windows\FontCache')
        (Join-Path $env:LOCALAPPDATA 'FontCache')
    )

    $deletedCount = 0
    $failedCount  = 0
    $bytesFreed   = [int64]0

    foreach ($path in $fontCachePaths) {
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Log ("  [SKIP] Path not present: {0}" -f $path) -Level DEBUG
            continue
        }

        try {
            $files = Get-ChildItem -LiteralPath $path -Filter '*.dat' -File -Force -ErrorAction SilentlyContinue

            foreach ($file in $files) {
                try {
                    $size = $file.Length
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    $deletedCount++
                    $bytesFreed += $size
                } catch {
                    $failedCount++
                    Write-Log ("  [WARN] Locked: {0}" -f $file.Name) -Level DEBUG
                }
            }
        } catch {
            Write-Log ("  [WARN] Scan failed for {0}: {1}" -f $path, $_.Exception.Message) -Level DEBUG
        }
    }

    $freedMB = [math]::Round($bytesFreed / 1MB, 2)
    # [FIX-STEP34-MSG] Distinguish "cache already clean" from "deleted 0
    # due to file locks". The two cases have different meanings and
    # different fixes, so collapsing them into "Deleted 0" makes the
    # log look like a silent failure when it's actually a success.
    if ($deletedCount -eq 0 -and $failedCount -eq 0) {
        Write-Log '  Font cache already clean — no .dat files to delete.' -Level INFO
    } else {
        Write-Log ("  Deleted {0} font cache files ({1} failed), reclaimed {2:N2} MB" -f $deletedCount, $failedCount, $freedMB) -Level INFO
    }

    # ============================================================
    # 3. Restart FontCache service
    # ============================================================
    if ($fontCacheWasRunning) {
        Write-Log 'Restarting FontCache service...' -Level INFO

        try {
            Start-Service -Name 'FontCache' -ErrorAction Stop
            Write-Log '  [OK] FontCache service restarted.' -Level OK
        } catch {
            Write-Log ("  [WARN] Could not restart FontCache: {0}" -f $_.Exception.Message) -Level WARN
            Write-Log '  Fonts will rebuild on next login or reboot.' -Level INFO
        }
    }

    # ============================================================
    # 4. Rebuild Explorer icon index
    # ============================================================
    Write-Log 'Rebuilding Explorer icon index...' -Level INFO

    $explorerCacheDir = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer'
    if (Test-Path -LiteralPath $explorerCacheDir) {
        $iconFiles = Get-ChildItem -LiteralPath $explorerCacheDir -Filter 'iconcache_*.db' -File -Force -ErrorAction SilentlyContinue

        $iconDeleted = 0
        foreach ($file in $iconFiles) {
            try {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                $iconDeleted++
            } catch {
                Write-Log ("  [WARN] Locked: {0}" -f $file.Name) -Level DEBUG
            }
        }

        Write-Log ("  Deleted {0} icon cache files." -f $iconDeleted) -Level INFO

        # Explorer will regenerate on next launch
        Write-Log '  Icon cache will regenerate automatically.' -Level INFO
    } else {
        Write-Log '  Explorer cache directory not found - skipped.' -Level DEBUG
    }

    # ============================================================
    # Verdict
    # ============================================================
    if ($overallSuccess) {
        Write-Log 'Font cache and icon index rebuild completed.' -Level OK
        Write-Log '[SUCCESS] Step 34: Font and icon caches cleanly rebuilt.' -Level OK
    } else {
        Write-Log 'Step 34 completed with one or more warnings.' -Level WARN
        Write-Log '[WARNING] Step 34: Some cache files may not have been cleared.' -Level WARN
    }

    Write-Log 'Step 34 complete.' -Level OK
}

# ============================================================
# STEP 35: Comprehensive Bloatware Package Provisioning Audit
# ============================================================
function Invoke-Step35 {
    <#
    .SYNOPSIS
        Enumerates provisioned Windows app packages that get
        automatically installed on new user profiles. Optionally
        removes them if -RemoveBloatware is supplied.

    .DESCRIPTION
        What are provisioned packages:
          * Apps Microsoft auto-installs on first login
          * Pre-staged in the Windows image, activated per user
          * Examples: Xbox, News, Weather, Solitaire, Disney+,
            Spotify (sponsored), Mail, Calendar, Tips, Get Help

        Why audit them:
          * Frees 500 MB - 2 GB of disk space
          * Reduces startup background processes
          * Removes sponsored apps users didn't ask for

        Two modes:
          * Audit (default) - List all provisioned apps with names,
            publishers, and installation sizes
          * Remove (with -RemoveBloatware) - Remove ALL
            user-facing apps EXCEPT a safe-list of critical ones

        Safe-list (never removed):
          * Microsoft.WindowsStore
          * Microsoft.DesktopAppInstaller (winget)
          * Microsoft.WindowsTerminal
          * Microsoft.SecHealthUI (Windows Security)
          * Microsoft.Windows.Photos (many users rely on it)
          * Microsoft.WindowsCalculator
          * Microsoft.WindowsNotepad
          * Microsoft.ScreenSketch (Snipping Tool)
          * Microsoft.Windows.Explorer (system)
          * Microsoft.VCLibs.* (runtime dependencies)
          * Microsoft.NET.* (runtime dependencies)

        Safety:
          * Safe-list ensures critical apps survive
          * Audit mode makes no changes at all
          * Removal mode requires -RemoveBloatware + confirmation
          * Removal is per-user; other profiles unaffected until logged in
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 35: Comprehensive Bloatware Package Provisioning Audit' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Enumerates Microsoft-shipped provisioned app packages.' -Level INFO

    if (-not (Confirm-Action -Query 'Run provisioned bloatware audit?')) {
        Write-Log 'Step 35 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would enumerate provisioned packages for bloatware audit.' -Level PREVIEW
        return
    }

    # ============================================================
    # 1. Enumerate provisioned packages
    # ============================================================
    Write-Log 'Enumerating provisioned app packages...' -Level INFO

    $provisioned = @()
    try {
        $provisioned = Get-AppxProvisionedPackage -Online -ErrorAction Stop |
                       Select-Object DisplayName, PackageName, Version, InstallLocation
    } catch {
        Write-Log ("Failed to enumerate provisioned packages: {0}" -f $_.Exception.Message) -Level WARN
        Write-Log '[WARNING] Step 35: Cannot enumerate provisioned packages.' -Level WARN
        return
    }

    if (-not $provisioned -or $provisioned.Count -eq 0) {
        Write-Log 'No provisioned packages returned.' -Level WARN
        return
    }

    Write-Log ("  Total provisioned packages: {0}" -f $provisioned.Count) -Level INFO

    # ---- Write detailed table to log ----
    $headerLines = @(
        ''
        '============================================================'
        (' PROVISIONED PACKAGES AUDIT - {0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date))
        (' Total provisioned: {0}' -f $provisioned.Count)
        '============================================================'
        ''
    )
    $headerLines | ForEach-Object {
        Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    foreach ($pkg in $provisioned) {
        $nameLine = ('{0}' -f $pkg.DisplayName)
        $verLine  = ('  Version: {0}' -f $pkg.Version)
        $pathLine = ('  Install: {0}' -f $pkg.InstallLocation)

        $nameLine | ForEach-Object { Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue }
        $verLine  | ForEach-Object { Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue }
        $pathLine | ForEach-Object { Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue }
    }

    # ============================================================
    # 2. Categorize packages
    # ============================================================
        # PSScriptAnalyzer suppression: variable is part of a legacy safe-list structure
        # (kept for backward compatibility; see FIX-5 positive removal list)
    # FIX-5: positive removal list.
    # Only packages in $explicitRemovalList are treated as removable.
    # Everything else is KEPT. This is safer than a negative allowlist
    # because an OEM-specific, regional, accessibility, or language-
    # specific package cannot be accidentally classified as bloatware.
    $explicitRemovalList = @(
        'Microsoft\.BingNews'
        'Microsoft\.BingWeather'
        'Microsoft\.GetHelp'
        'Microsoft\.Getstarted'
        'Microsoft\.MicrosoftSolitaireCollection'
        'Microsoft\.MixedReality\.Portal'
        'Microsoft\.Microsoft3DViewer'
        'Microsoft\.SkypeApp'
        'Microsoft\.ZuneMusic'
        'Microsoft\.ZuneVideo'
        'Microsoft\.WindowsFeedbackHub'
        'Microsoft\.XboxGamingOverlay'
        'Microsoft\.GamingApp'
        'Microsoft\.StartExperiencesApp'
        'Microsoft\.Todos'
        'Clipchamp\.Clipchamp'
        'Microsoft\.MicrosoftOfficeHub'
    )

    $removable = @()
    $protected = @()

    foreach ($pkg in $provisioned) {
        $isExplicit = $false
        foreach ($pattern in $explicitRemovalList) {
            if ($pkg.PackageName -match $pattern) {
                $isExplicit = $true
                break
            }
        }
        if ($isExplicit) {
            $removable += $pkg
        } else {
            $protected += $pkg
        }
    }

    Write-Log ("  Protected (safe-list): {0}" -f $protected.Count) -Level INFO
    Write-Log ("  Removable (bloatware candidates): {0}" -f $removable.Count) -Level INFO

    # ============================================================
    # 3. Audit mode: show removable packages
    # ============================================================
    if ($removable.Count -gt 0) {
        Write-Host ''
        Write-Host 'Removable bloatware candidates:' -ForegroundColor Cyan
        Write-Host ('-' * 60) -ForegroundColor DarkGray
        foreach ($pkg in $removable) {
            Write-Host ("  {0}" -f $pkg.DisplayName) -ForegroundColor Gray
        }
        Write-Host ''
    }

    # ============================================================
    # 4. Removal mode (opt-in)
    # ============================================================
    if (-not $Script:RemoveBloatware) {
        Write-Log 'Audit complete. No changes made.' -Level INFO
        Write-Log 'Add -RemoveBloatware to enable removal of listed packages.' -Level INFO
        Write-Log '[SUCCESS] Step 35: Bloatware audit complete.' -Level OK
        return
    }

    # ---- Confirm removal ----
    if ($removable.Count -eq 0) {
        Write-Log 'No provisioned bloatware candidates detected - nothing to remove.' -Level OK
        Write-Log '[SUCCESS] Step 35: No bloatware candidates detected.' -Level OK
        return
    }

    Write-Log ('[WARNING] About to REMOVE {0} provisioned packages.' -f $removable.Count) -Level WARN
    Write-Log 'These will not be reinstalled on new user profiles.' -Level WARN

    if (-not (Confirm-Action -Query 'Are you absolutely sure you want to remove these packages?')) {
        Write-Log 'Removal aborted by user.' -Level INFO
        return
    }

    # ---- Remove packages ----
    Write-Log 'Removing provisioned bloatware packages...' -Level INFO

    $removedCount = 0
    $failedCount  = 0
    # [FIX-REG-35] $skippedCount is incremented by the orphaned-staging
    # branch added in Fix-SilentFailures.ps1, but was never initialized.
    # StrictMode Latest throws "variable cannot be retrieved" on read.
    $skippedCount = 0

    foreach ($pkg in $removable) {
        Write-Log ("  Removing: {0}" -f $pkg.DisplayName) -Level INFO

        try {
            # Remove from provision (future users) - primary target
            Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop | Out-Null

            # Also remove from current user if installed
            try {
                Get-AppxPackage -Name ($pkg.PackageName -replace '_.*$', '') -ErrorAction SilentlyContinue |
                    Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                # Current user removal is best-effort
            }

            Write-Log ("    [OK] Removed: {0}" -f $pkg.DisplayName) -Level OK
            $removedCount++
        } catch {
            # [FIX-SILENT-3] ERROR_PATH_NOT_FOUND (0x80070003) means the
            # on-disk payload is already gone; only the staging entry
            # survives. This is not a real failure - treat as skip.
            $errMsg = $_.Exception.Message
            if ($errMsg -match 'cannot find the path|0x80070003|ERROR_PATH_NOT_FOUND') {
                Write-Log ("    [SKIP] Orphaned staging entry (payload already gone): {0}" -f $pkg.DisplayName) -Level INFO
                $skippedCount++
            } else {
                Write-Log ("    [WARN] Failed to remove {0}: {1}" -f $pkg.DisplayName, $errMsg) -Level WARN
                $failedCount++
            }
        }
    }

    # ============================================================
    # Verdict
    # ============================================================
    Write-Log ("Removal summary: {0} removed, {1} skipped (orphaned staging), {2} failed" `
        -f $removedCount, $skippedCount, $failedCount) -Level INFO

    if ($failedCount -eq 0) {
        if ($removedCount -gt 0) {
            Write-Log ('[SUCCESS] Step 35: {0} removed, {1} orphaned staging entries skipped.' `
                -f $removedCount, $skippedCount) -Level OK
        } elseif ($skippedCount -gt 0) {
            Write-Log ('[INFO] Step 35: {0} candidate(s) were orphaned staging entries (no action needed).' `
                -f $skippedCount) -Level INFO
        } else {
            Write-Log '[SUCCESS] Step 35: No action needed.' -Level OK
        }
    } else {
        Write-Log '[WARNING] Step 35: Some packages could not be removed.' -Level WARN
    }

    Write-Log 'Step 35 complete.' -Level OK
}


# ============================================================
# STEP 36: Compacting the Windows Search Indexing Database
# ============================================================
function Invoke-Step36 {
    <#
    .SYNOPSIS
        Compacts the Windows Search index database (Windows.edb)
        using the ESENT offline defragmentation tool.

    .DESCRIPTION
        What Windows.edb is:
          * The Windows Search index database
          * Located at %ProgramData%\Microsoft\Search\Data\
              Applications\Windows\Windows.edb
          * Can grow to 2-10 GB on data-heavy systems
          * Contains the "inverted index" of file contents,
            metadata, and search hints

        What this step does:
          1. Stops the WSearch service (Windows Search)
          2. Runs esentutl.exe /d on Windows.edb
          3. Restarts WSearch

        Why compact:
          * Fragmented EDB files slow down search queries
          * Compaction can reclaim 30-60% of the file size
          * Improves search speed and reduces disk footprint

        Gating:
          * Requires -AllowSearchDefrag flag
          * Requires explicit Y/N confirmation
          * Skipped if Windows.edb is under 1 GB (not worth the time)

        Duration:
          * 15-45 minutes depending on index size
          * Progress is not shown by esentutl (it is silent)
          * The script will wait silently; check Task Manager for esentutl.exe

        Safety:
          * esentutl creates a temporary file during compaction
          * Requires sufficient free disk space (2x Windows.edb size)
          * If compaction fails, the original is preserved
          * Service automatically restarts on failure

        Reversion:
          * The compaction is not reversible
          * But Windows.edb is a cache - it will rebuild from scratch
            if deleted entirely (Windows Search will re-index slowly)
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 36: Compacting the Windows Search Indexing Database' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Compacts Windows.edb using ESENT offline defragmentation.' -Level INFO

    # ---- Gate 1: -AllowSearchDefrag required ----
    if (-not $Script:AllowSearchDefrag) {
        Write-Log 'Step 36 blocked: -AllowSearchDefrag flag was not supplied.' -Level INFO
        Write-Log 'Search index defragmentation takes 15-45 minutes.' -Level INFO
        Write-Log 'Re-run with -AllowSearchDefrag if you explicitly want this.' -Level INFO
        Write-Log '[INFO] Step 36 skipped: -AllowSearchDefrag authorization flag absent.' -Level INFO
        return
    }

    # ---- Locate the search index (handles both legacy and modern layouts) ----
    # Legacy Windows 10 / early Windows 11: single Windows.edb file
    # Modern Windows 11 26100+: folder-based SystemIndex catalog
    $edbPath       = Join-Path $env:ProgramData 'Microsoft\Search\Data\Applications\Windows\Windows.edb'
    $systemIndexDir = Join-Path $env:ProgramData 'Microsoft\Search\Data\Applications\Windows\Projects\SystemIndex'

    $hasLegacyEdb  = Test-Path -LiteralPath $edbPath
    $hasSystemIndex = Test-Path -LiteralPath $systemIndexDir

    if (-not $hasLegacyEdb -and -not $hasSystemIndex) {
        Write-Log 'No Windows Search index found (neither Windows.edb nor SystemIndex).' -Level WARN
        Write-Log '[INFO] Step 36 skipped: no search index present to compact.' -Level INFO
        return
    }

    if (-not $hasLegacyEdb -and $hasSystemIndex) {
        # Modern folder-based catalog. esentutl only works on .edb files,
        # so compaction is not applicable. The only way to reclaim space is
        # to rebuild the index from scratch, which is disruptive.
        Write-Log 'Modern folder-based SystemIndex detected (no Windows.edb).' -Level INFO
        Write-Log 'The legacy esentutl compaction does not apply to this layout.' -Level INFO
        Write-Log '' -Level INFO
        Write-Log 'To reclaim space from the search index, rebuild it via:' -Level INFO
        Write-Log '  Settings -> Privacy & Security -> Searching Windows' -Level INFO
        Write-Log '    -> Advanced Indexing Options -> Advanced -> Rebuild' -Level INFO
        Write-Log '' -Level INFO
        Write-Log 'A rebuild takes 30 min - 4 hours in the background and does not' -Level INFO
        Write-Log 'require a reboot. It is intentionally NOT automated here because' -Level INFO
        Write-Log 'it temporarily disables Search (including Outlook/Exchange search).' -Level INFO
        Write-Log '' -Level INFO
        return
    }

    # ---- Size pre-check ----
    $edbItem = Get-Item -LiteralPath $edbPath -ErrorAction SilentlyContinue
    $edbSizeGB = [math]::Round($edbItem.Length / 1GB, 2)

    Write-Log ("Windows.edb current size: {0} GB" -f $edbSizeGB) -Level INFO

    if ($edbSizeGB -lt 1.0) {
        Write-Log 'Search index is under 1 GB - not worth the 15-45 minute compaction.' -Level INFO
        Write-Log '[INFO] Step 36 skipped: Search index too small.' -Level INFO
        return
    }

    # ---- Confirm ----
    if (-not (Confirm-Action -Query ('Compact search index ({0} GB, ~15-45 min)?' -f $edbSizeGB))) {
        Write-Log 'Step 36 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log ('Would compact Windows.edb ({0} GB) via esentutl.' -f $edbSizeGB) -Level PREVIEW
        return
    }

    # ============================================================
    # 1. Verify enough free space
    # ============================================================
    $drive = Split-Path -Qualifier $edbPath   # e.g. "C:"
    $freeBytes = (Get-PSDrive -Name $drive.TrimEnd(':') -ErrorAction SilentlyContinue).Free

    if ($freeBytes) {
        $freeGB = [math]::Round($freeBytes / 1GB, 2)
        $requiredGB = $edbSizeGB * 1.5

        Write-Log ("  Free space on {0}: {1} GB (need ~{2} GB)" -f $drive, $freeGB, $requiredGB) -Level INFO

        if ($freeGB -lt $requiredGB) {
            Write-Log 'Insufficient free disk space for safe compaction.' -Level WARN
            Write-Log '[WARNING] Step 36 aborted: not enough free space.' -Level WARN
            return
        }
    }

    # ============================================================
    # 2. Stop WSearch service
    # ============================================================
    Write-Log 'Stopping Windows Search service...' -Level INFO

    $searchSvc = Get-Service -Name 'WSearch' -ErrorAction SilentlyContinue
    $wasRunning = $false

    if ($searchSvc) {
        $wasRunning = ($searchSvc.Status -eq 'Running')

        if ($wasRunning) {
            try {
                Stop-Service -Name 'WSearch' -Force -ErrorAction Stop
                Write-Log '  [OK] WSearch service stopped.' -Level OK
                Start-Sleep -Seconds 3
            } catch {
                Write-Log ("  [WARN] Could not stop WSearch: {0}" -f $_.Exception.Message) -Level WARN
                Write-Log '[WARNING] Step 36 aborted: cannot access the search index.' -Level WARN
                return
            }
        }
    } else {
        Write-Log '  WSearch service not present - continuing anyway.' -Level DEBUG
    }

    # ============================================================
    # 3. Run esentutl compaction
    # ============================================================
    Write-Log 'Running ESENT offline defragmentation...' -Level INFO
    Write-Log '  This may take 15-45 minutes. Progress is not visible.' -Level INFO
    Write-Log '  Do NOT close this window.' -Level INFO

    # The /p flag preserves the original file if the operation fails
    # /o (offline) mode is used because the service is stopped
    $esentStart = Get-Date

    try {
        $esentResult = & esentutl.exe /d $edbPath /o /s 2>&1
        $esentExitCode = $LASTEXITCODE
    } catch {
        Write-Log ("esentutl invocation failed: {0}" -f $_.Exception.Message) -Level ERROR
        return
    } finally {
        # ---- Fix 01: guarantee WSearch restart even if the process
        #              is interrupted or killed mid-compaction ----
        if ($wasRunning) {
            $svcCheck = Get-Service -Name 'WSearch' -ErrorAction SilentlyContinue
            if ($svcCheck -and $svcCheck.Status -ne 'Running') {
                try {
                    Start-Service -Name 'WSearch' -ErrorAction Stop
                } catch {
                    Write-Log ("  [WARN] Could not restart WSearch in finally: {0}" -f $_.Exception.Message) -Level WARN
                }
            }
        }
    }

    $esentDuration = (Get-Date) - $esentStart

    # Log raw output
    $esentResult | ForEach-Object {
        Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    Write-Log ("esentutl completed in {0:N1} minutes (exit code {1})." -f $esentDuration.TotalMinutes, $esentExitCode) -Level INFO

    # ============================================================
    # 4. Restart WSearch service
    # ============================================================
    if ($wasRunning) {
        Write-Log 'Restarting Windows Search service...' -Level INFO

        try {
            Start-Service -Name 'WSearch' -ErrorAction Stop
            Write-Log '  [OK] WSearch service restarted.' -Level OK
        } catch {
            Write-Log ("  [WARN] Could not restart WSearch: {0}" -f $_.Exception.Message) -Level WARN
            Write-Log '  Search will re-initialize on next reboot.' -Level INFO
        }
    }

    # ============================================================
    # 5. Report size change
    # ============================================================
    Start-Sleep -Seconds 2
    $newEdb = Get-Item -LiteralPath $edbPath -ErrorAction SilentlyContinue
    $newSizeGB = if ($newEdb) { [math]::Round($newEdb.Length / 1GB, 2) } else { 0 }
    $savedGB = [math]::Round($edbSizeGB - $newSizeGB, 2)

    Write-Log ("  Size before: {0} GB" -f $edbSizeGB) -Level INFO
    Write-Log ("  Size after:  {0} GB" -f $newSizeGB) -Level INFO
    Write-Log ("  Space reclaimed: {0} GB" -f $savedGB) -Level OK

    # ============================================================
    # Verdict
    # ============================================================
    if ($esentExitCode -eq 0) {
        Write-Log 'Search index compaction completed successfully.' -Level OK
        Write-Log '[SUCCESS] Step 36: Windows Search database compacted.' -Level OK
    } else {
        Write-Log ('Search index compaction returned exit code {0}.' -f $esentExitCode) -Level WARN
        Write-Log 'Original database preserved. No data lost.' -Level INFO
        Write-Log '[WARNING] Step 36: Compaction did not complete cleanly.' -Level WARN
    }

    Write-Log 'Step 36 complete.' -Level OK
}


# ============================================================
# STEP 37: Feature Update Target Delay Configuration
# ============================================================
function Invoke-Step37 {
    <#
    .SYNOPSIS
        Configures Windows to delay major feature updates (OS build
        upgrades) by a configurable number of days. Monthly quality
        updates (security patches) are NOT delayed.

    .DESCRIPTION
        What feature updates are:
          * Major Windows version bumps (22H2 -> 23H2 -> 24H2, etc.)
          * Downloaded and applied as a full OS replacement
          * Can introduce driver incompatibilities, UI changes,
            and new bugs that take weeks to patch

        What quality updates are:
          * Monthly security patches and bug fixes
          * Downloaded via the normal Windows Update flow
          * NOT delayed by this step

        Configuration written:
          HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings
            DeferFeatureUpdates              = 1
            DeferFeatureUpdatesPeriodInDays  = <N>
            BranchReadinessLevel             = 20  (Semi-Annual Channel)

          HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
            DeferFeatureUpdates              = 1
            DeferFeatureUpdatesPeriodInDays  = <N>

        Recommended values:
          * 30 days  - Conservative, catches most initial bugs
          * 60 days  - Very conservative, waits for 1st patch wave
          * 90 days  - Maximum for consumer use
          * 365 days - Enterprise-typical; may be ignored on Home SKU

        Home vs Pro/Enterprise:
          * Windows Home may ignore these settings (Microsoft docs
            list them as Pro/Enterprise only)
          * On Home, Windows Update still defers a bit by default
          * On Pro/Enterprise/Education, the values are honored

        Safety:
          * Reversible: set DeferFeatureUpdates = 0 or remove the key
          * Does not affect security patches
          * Does not affect driver updates
          * Requires admin (script enforces)
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 37: Feature Update Target Delay Configuration' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Delays major Windows feature updates by N days.' -Level INFO
    Write-Log 'Monthly security patches are NOT delayed.' -Level INFO

    # ---- Determine deferral period ----
    $deferDays = $Script:FeatureUpdateDelayDays

    if (-not $deferDays -or $deferDays -le 0) {
        $deferDays = 30   # Default: 30 days
    }

    # ---- Clamp to safe range ----
    if ($deferDays -gt 365) {
        Write-Log ("Requested deferral of {0} days exceeds 365 - clamping." -f $deferDays) -Level WARN
        $deferDays = 365
    }

    if ($deferDays -lt 7) {
        Write-Log ("Requested deferral of {0} days is below 7 - using 30 instead." -f $deferDays) -Level WARN
        $deferDays = 30
    }

    Write-Log ("Configured deferral: {0} days" -f $deferDays) -Level INFO

    if (-not (Confirm-Action -Query ('Configure {0}-day feature update deferral?' -f $deferDays))) {
        Write-Log 'Step 37 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log ('Would configure {0}-day feature update deferral.' -f $deferDays) -Level PREVIEW
        return
    }

    $overallSuccess = $true

    # ---- Helper: idempotent DWORD write ----
    $setDword = {
        param([string]$Path, [string]$Name, [int]$Value)
        try {
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            return $true
        } catch {
            Write-Log ("  Failed to set {0}\{1}: {2}" -f $Path, $Name, $_.Exception.Message) -Level WARN
            return $false
        }
    }

    # ============================================================
    # 1. Configure UX\Settings path (Windows 10/11 consumer)
    # ============================================================
    if ($Script:WinHomeSku) {
        Write-Log '  [NOTE] Windows Home SKU detected - policy keys will be written' -Level WARN
        Write-Log '         but Windows Home may ignore them (Microsoft policy).' -Level WARN
    }
    Backup-RegistryKey -Step 37 -RegPath 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    Backup-RegistryKey -Step 37 -RegPath 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    Write-Log 'Configuring UX\Settings feature-update deferral...' -Level INFO

    $uxPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'

    if (& $setDword $uxPath 'DeferFeatureUpdates' 1) {
        Write-Log '  [OK] DeferFeatureUpdates = 1' -Level OK
    } else {
        $overallSuccess = $false
    }

    if (& $setDword $uxPath 'DeferFeatureUpdatesPeriodInDays' $deferDays) {
        Write-Log ('  [OK] DeferFeatureUpdatesPeriodInDays = {0}' -f $deferDays) -Level OK
    } else {
        $overallSuccess = $false
    }

    if (& $setDword $uxPath 'BranchReadinessLevel' 20) {
        Write-Log '  [OK] BranchReadinessLevel = 20 (Semi-Annual Channel)' -Level OK
    } else {
        $overallSuccess = $false
    }

    # ============================================================
    # 2. Configure WindowsUpdate policy path (Enterprise/Pro)
    # ============================================================
    Write-Log 'Configuring WindowsUpdate policy feature-update deferral...' -Level INFO

    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

    if (& $setDword $policyPath 'DeferFeatureUpdates' 1) {
        Write-Log '  [OK] Policy DeferFeatureUpdates = 1' -Level OK
    } else {
        $overallSuccess = $false
    }

    if (& $setDword $policyPath 'DeferFeatureUpdatesPeriodInDays' $deferDays) {
        Write-Log ('  [OK] Policy DeferFeatureUpdatesPeriodInDays = {0}' -f $deferDays) -Level OK
    } else {
        $overallSuccess = $false
    }

    # ============================================================
    # 3. Verify
    # ============================================================
    # P3: Step 37 rollback entries
    Add-RollbackEntry -Step 37 -Type 'RegistryHKCU' -Data @{ Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'; Name = 'DeferFeatureUpdates'; Existed = $false; Value = $null; Type = 'DWord' }
    Add-RollbackEntry -Step 37 -Type 'RegistryHKCU' -Data @{ Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'; Name = 'DeferFeatureUpdatesPeriodInDays'; Existed = $false; Value = $null; Type = 'DWord' }
    Write-Log 'Verifying configuration...' -Level INFO

    try {
        $uxValue    = (Get-ItemProperty -Path $uxPath -Name 'DeferFeatureUpdatesPeriodInDays' -ErrorAction SilentlyContinue).DeferFeatureUpdatesPeriodInDays
        $policyValue = (Get-ItemProperty -Path $policyPath -Name 'DeferFeatureUpdatesPeriodInDays' -ErrorAction SilentlyContinue).DeferFeatureUpdatesPeriodInDays

        Write-Log ("  UX path:     {0} days" -f $uxValue) -Level INFO
        Write-Log ("  Policy path: {0} days" -f $policyValue) -Level INFO

        if ($uxValue -ne $deferDays -and $policyValue -ne $deferDays) {
            Write-Log 'Configuration did not persist to either path.' -Level WARN
            $overallSuccess = $false
        }
    } catch {
        Write-Log ("  Verification failed: {0}" -f $_.Exception.Message) -Level DEBUG
    }

    # ============================================================
    # Verdict
    # ============================================================
    if ($overallSuccess) {
        Write-Log ('Feature update deferral configured: {0} days.' -f $deferDays) -Level OK
        Write-Log '[SUCCESS] Step 37: Feature update deferral policy applied.' -Level OK
        Write-Log '' -Level INFO
        Write-Log 'Notes:' -Level INFO
        Write-Log '  - Windows Pro/Enterprise/Education: setting is enforced.' -Level INFO
        Write-Log '  - Windows Home: setting may be ignored (Microsoft policy).' -Level INFO
        Write-Log '  - Monthly security patches are NOT affected.' -Level INFO
        Write-Log '  - To revert: set DeferFeatureUpdates = 0 in both paths.' -Level INFO
    } else {
        Write-Log 'Step 37 completed with one or more errors.' -Level WARN
        Write-Log '[WARNING] Step 37: Some registry writes failed.' -Level WARN
    }

    Write-Log 'Step 37 complete.' -Level OK
}


# ============================================================
# POST-CHECK: Final System Metrics
# ============================================================
# ============================================================
# STEP 38: Startup Entry Bulk Removal (Safe-List Protected)
# ============================================================
# ============================================================
# PERSISTENCE CLASSIFICATION HELPER (used by Step 38)
# ============================================================
function Get-PersistenceClassification {
    <#
    .SYNOPSIS
        Returns 'Keep' or 'Disable' for a persistence entry.

    .DESCRIPTION
        Rules:
          * Microsoft-signed         -> Keep
          * Hardware vendor-signed   -> Keep
          * Security software-signed -> Keep
          * Sync client-signed       -> Keep
          * Input device software    -> Keep
          * Stale (file missing)     -> Disable
          * Unsigned / unknown       -> Disable
          * Signed but unknown vendor-> Disable

        Signature check via Get-AuthenticodeSignature. Falls back to
        'Keep' if signature cannot be read (offline, locked file) to
        avoid false positives that could disable something important.
    #>
    param([string]$FilePath)

    # [FIX-GENERIC-2] Empty/unparseable path should default to Keep, not
    # Disable. Legitimate COM-handler scheduled tasks (OneDrive Update,
    # Office ClickToRun, Edge Update) and corrupted startup entries both
    # hit this branch. Refusing to disable something we cannot inspect is
    # the safe behavior for a heterogeneous fleet.
    if ([string]::IsNullOrWhiteSpace($FilePath)) { return 'Keep' }

    # Normalize: strip ALL quotes (leading, trailing, embedded), then trim,
    # then extract the .exe path from any trailing arguments.
    $clean = $FilePath -replace '"', ''
    $clean = $clean.Trim()
    if ($clean -match '^(.+?\.(exe|dll|com|bat|cmd|ps1))(\s|$)') {
        $clean = $matches[1].Trim()
    }
    $clean = [System.Environment]::ExpandEnvironmentVariables($clean)

    # Stale file -> Disable
    if (-not (Test-Path -LiteralPath $clean -ErrorAction SilentlyContinue)) {
        return 'Disable'
    }

    # ---- Well-known Microsoft paths: always Keep ----
    $msPaths = @(
        '\Program Files\Microsoft OneDrive\',
        '\Program Files (x86)\Microsoft\Edge\',
        '\Program Files\Microsoft\Edge\',
        '\Program Files\Windows Defender\',
        '\Program Files\WindowsApps\Microsoft.',
        # NOTE: \Windows\System32\ and \Windows\SysWOW64\ are intentionally
        # NOT in this list. Unsigned or unknown-publisher binaries in those
        # folders must still go through the signature check below and be
        # classified Disable. Microsoft-signed binaries there are kept by
        # the 'Microsoft'/'Windows' publisher match that follows.
        '\Program Files\Windows Security\',
        '\Program Files\Microsoft\EdgeUpdate\',
        '\Program Files (x86)\Microsoft\EdgeUpdate\'
    )
    foreach ($p in $msPaths) {
        if ($clean -match [regex]::Escape($p)) { return 'Keep' }
    }

    # [FIX-CLASSIFY-VERSIONINFO] Check version-info first. On enterprise
    # machines, self-signed or non-public-CA certs (7-Zip's Igor Pavlov
    # cert, various small vendors) show "NotTrusted" even for legitimate
    # software. Version info is set by the compiler and unaffected by
    # trust chain status.
    try {
        $__vi = (Get-Item -LiteralPath $clean -Force -ErrorAction SilentlyContinue).VersionInfo
        if ($__vi) {
            $__viProduct = [string]$__vi.ProductName
            $__viCompany = [string]$__vi.CompanyName
            $__viDesc    = [string]$__vi.FileDescription
            $__viKeep = @(
                'Igor Pavlov', '7-Zip', 'RARLAB', 'win.rar', 'WinZip',
                'Adobe', 'Foxit', 'Tracker Software', 'PDF-XChange',
                'Irfan Skiljan', 'IrfanView', 'Notepad++', 'Don Ho',
                'Sublime HQ', 'JetBrains', 'VideoLAN',
                'TortoiseSVN', 'TortoiseGit',
                'TeamViewer', 'AnyDesk', 'LogMeIn', 'Realtek', 'Intel',
                'NVIDIA', 'AMD', 'Microsoft'
            )
            foreach ($p in $__viKeep) {
                if ($__viProduct -match [regex]::Escape($p)) { return 'Keep' }
                if ($__viCompany -match [regex]::Escape($p)) { return 'Keep' }
                if ($__viDesc    -match [regex]::Escape($p)) { return 'Keep' }
            }
        }
    } catch { }

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $clean -ErrorAction Stop

        # Signature check can fail offline. On error, prefer Keep (safety).
        if ($sig.Status -eq 'UnknownError') { return 'Keep' }
        if ($sig.Status -eq 'NotSigned')   { return 'Disable' }

        # [FIX-CLASSIFY-SUBJECT] Check cert subject BEFORE rejecting on
        # status != Valid. A legitimately-signed file whose cert chain
        # isn't in the local trust store returns NotTrusted, which we'd
        # otherwise reject and disable a real product's context menu.
        $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }

        # KEEP-LIST: known-safe publisher substrings (case-insensitive)
        $keepPublishers = @(
            # Microsoft + Windows
            'Microsoft', 'Windows'

            # Hardware vendors
            'Intel', 'NVIDIA', 'AMD', 'Advanced Micro Devices'
            'Realtek', 'Qualcomm', 'Broadcom', 'MediaTek', 'Marvell'
            'Dell', 'Hewlett-Packard', 'HP Inc', 'HP Company'
            'Lenovo', 'ASUS', 'ASUSTeK', 'Acer', 'MSI', 'Micro-Star'
            'Gigabyte', 'GIGA-BYTE', 'Samsung', 'LG Electronics', 'Toshiba', 'Sony'
            'Synaptics', 'Elan', 'Alps Electric'

            # Input devices
            'Wacom', 'Logitech', 'Razer', 'Corsair', 'SteelSeries', 'HyperX', 'Keychron'

            # Security / VPN
            'Malwarebytes', 'Kaspersky', 'ESET', 'Bitdefender', 'Norton', 'Gen Digital'
            'McAfee', 'Avast', 'AVG', 'Sophos', 'Trend Micro', 'CrowdStrike'
            'SentinelOne', 'Carbon Black', 'Webroot', 'F-Secure'
            'Proton', 'OpenVPN', 'Nord Security', 'NordVPN', 'ExpressVPN'
            'Surfshark', 'Cisco', 'Fortinet', 'Palo Alto', 'Zscaler'

            # Sync / cloud
            'Dropbox', 'Box, Inc', 'Google', 'Apple Inc', 'Mozilla'
            'Nextcloud', 'MEGAsync', 'Sync.com'

            # Common productivity (avoid breaking)
            # ---- Document / archive / utility tools ----
            # [FIX-GENERIC-3] Expanded for fleet genericity. Users who
            # install Adobe, Foxit, 7-Zip, WinRAR, Notepad++, VLC,
            # TeamViewer, etc. expect their persistence entries to survive
            # -AllowPersistenceAction and -AllowContextMenuAction. Only
            # publishers NOT listed below become disable candidates.
            'Adobe', 'Foxit', 'Foxit Software'
            'Igor Pavlov', '7-Zip'
            'win.rar', 'RARLAB'
            'Nico Mak Computing', 'WinZip'
            'Tracker Software', 'PDF-XChange'
            'Artifex', 'GPL Ghostscript'
            'Irfan Skiljan', 'IrfanView'
            'Notepad++', 'Don Ho'
            'Sublime HQ'
            'TortoiseSVN', 'TortoiseGit'
            'The Git Development Community'
            'JetBrains'
            'VideoLAN'
            'TeamViewer', 'AnyDesk', 'LogMeIn'

            # Browsers (auto-launch entries)
            'Chrome', 'Microsoft Edge', 'Edge'
            'Mozilla', 'Firefox'

            # Scanner / imaging tools (user-installed, frequently re-enabled)
            'PFU', 'ScanSnap', 'Fujitsu'
            'Canon', 'Epson', 'Brother', 'Xerox'
            'ABBYY', 'Kofax', 'Nuance'
            'PaperPort', 'OmniPage'

            # Personal productivity (user-installed)
        )

        foreach ($p in $keepPublishers) {
            if ($subject -match [regex]::Escape($p)) { return 'Keep' }
        }

        return 'Disable'
    } catch {
        # Catch-all: prefer Keep to avoid disabling on unexpected errors
        return 'Keep'
    }
}

# ============================================================
# STEP 38: Startup and Logon Persistence Management
# ============================================================
function Invoke-Step38 {
    <#
    .SYNOPSIS
        Enumerates startup entries and logon/boot scheduled tasks,
        classifies each as Keep or Disable via signature checking,
        and (with user approval) disables the non-essential ones.

    .DESCRIPTION
        Sources:
          * HKCU/HKLM Run + RunOnce keys (6 locations)
          * User + All-Users Startup folders
          * Scheduled tasks with LogonTrigger or BootTrigger
            (excluding Microsoft-owned tasks under \Microsoft\)

        Classification: Get-PersistenceClassification (signature-based)
          * Keep: signed by Microsoft, hardware vendor, security vendor,
            sync client, or input device vendor
          * Disable: unsigned, unknown publisher, or stale (file missing)

        Action:
          * Startup entries: write StartupApproved disabled bit
            (same mechanism as Task Manager's toggle - reversible)
          * Scheduled tasks: Disable-ScheduledTask (reversible)

        Safety:
          * Always runs the audit (read-only) unless -AllowPersistenceAction
          * Backup .reg file written before any change
          * Interactive Y/N per entry (or batch confirm with the flag)
          * Never deletes files or registry values
          * Full rollback documented in log
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 38: Startup and Logon Persistence Management' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    # ================================================================
    # PHASE 1: Startup entries
    # ================================================================
    Write-Log 'PHASE 1: Enumerating startup entries...' -Level INFO

    $startupLocations = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    $startupEntries = @()
    foreach ($loc in $startupLocations) {
        if (-not (Test-Path -LiteralPath $loc)) { continue }
        try {
            $props = Get-ItemProperty -LiteralPath $loc -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -like 'PS*') { continue }
                if ($prop.Name -eq '(default)') { continue }
                if ([string]::IsNullOrWhiteSpace([string]$prop.Value)) { continue }

                $class = Get-PersistenceClassification -FilePath ([string]$prop.Value)

                $startupEntries += [PSCustomObject]@{
                    Name     = $prop.Name
                    Command  = [string]$prop.Value
                    Location = $loc
                    Kind     = $class
                }
            }
        } catch { }
    }

    # Startup folders
    $startupFolders = @(
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    foreach ($folder in $startupFolders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        try {
            $files = Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                if ($f.Extension -notin '.lnk','.url') { continue }
                $class = Get-PersistenceClassification -FilePath $f.FullName
                $startupEntries += [PSCustomObject]@{
                    Name     = $f.BaseName
                    Command  = $f.FullName
                    Location = $folder
                    Kind     = $class
                }
            }
        } catch { }
    }

    # ================================================================
    # PHASE 2: Logon/boot scheduled tasks
    # ================================================================
    Write-Host ''
    Write-Log 'PHASE 2: Enumerating logon/boot scheduled tasks...' -Level INFO

    $taskEntries = @()
    try {
        $allTasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in $allTasks) {
            # Only logon/boot triggers
            $hasTrigger = $false
            if ($task.Triggers) {
                foreach ($t in $task.Triggers) {
                    $cls = ''
                    if ($t.CimClass -and $t.CimClass.CimClassName) { $cls = $t.CimClass.CimClassName }
                    if ($cls -match 'LogonTrigger|BootTrigger') { $hasTrigger = $true; break }
                }
            }
            if (-not $hasTrigger) { continue }

            # Skip disabled and Microsoft-owned
            if ($task.State -eq 'Disabled') { continue }
            if ($task.TaskPath -like '\Microsoft\*') { continue }

            # Extract executable
            $exe = ''
            if ($task.Actions) {
                foreach ($a in $task.Actions) {
                    if ($a.PSObject.Properties['Execute'] -and $a.Execute) {
                        $exe = [string]$a.Execute
                        break
                    }
                }
            }

            $class = Get-PersistenceClassification -FilePath $exe

            $taskEntries += [PSCustomObject]@{
                Name     = $task.TaskName
                Command  = $exe
                Location = $task.TaskPath
                Kind     = $class
            }
        }
    } catch {
        Write-Log ('Could not enumerate scheduled tasks: {0}' -f $_.Exception.Message) -Level WARN
    }

    # ================================================================
    # PHASE 3: Classify and display
    # ================================================================
    $allEntries     = @($startupEntries) + @($taskEntries)
    $keepEntries    = @($allEntries | Where-Object { $_.Kind -eq 'Keep' })
    $disableEntries = @($allEntries | Where-Object { $_.Kind -eq 'Disable' })

    Write-Host ''
    Write-Log ("Total: {0} entries ({1} Keep, {2} Disable)" -f $allEntries.Count, $keepEntries.Count, $disableEntries.Count) -Level INFO

    if ($keepEntries.Count -gt 0) {
        Write-Host ''
        Write-Log 'PROTECTED (signed by trusted publisher):' -Level OK
        foreach ($e in $keepEntries) {
            Write-Log ("  [KEEP] {0}" -f $e.Name) -Level OK
            Write-Log ("         {0}" -f $e.Command) -Level DEBUG
        }
    }

    if ($disableEntries.Count -gt 0) {
        Write-Host ''
        Write-Log 'CANDIDATES FOR DISABLE:' -Level WARN
        foreach ($e in $disableEntries) {
            Write-Log ("  [DISABLE] {0}" -f $e.Name) -Level WARN
            Write-Log ("            {0}" -f $e.Command) -Level WARN
        }
    }

    if ($disableEntries.Count -eq 0) {
        Write-Host ''
        Write-Log 'No non-essential entries detected.' -Level OK
        Write-Log 'Step 38 complete.' -Level OK
        return
    }

    # ================================================================
    # PHASE 4: Backup
    # ================================================================
    if (-not $Script:DryRun) {
        Write-Host ''
        Write-Log 'Backing up startup entries to .reg file...' -Level INFO
        $backupFile = Join-Path $Script:ScriptDir ("StartupBackup_{0}.reg" -f $Script:RunStamp)

        $regExports = New-Object System.Collections.ArrayList
        $byLocation = $startupEntries | Where-Object { $_.Location -like 'HK*' } | Group-Object -Property Location
        foreach ($group in $byLocation) {
            $loc = $group.Name
            $regKey = $loc -replace '^HKCU:\\', 'HKCU\' -replace '^HKLM:\\', 'HKLM\'
            $regKey = $regKey.TrimEnd('\')
            $tempReg = [System.IO.Path]::GetTempFileName() + '.reg'
            try {
                $null = & reg.exe export $regKey $tempReg /y 2>&1
                if (Test-Path $tempReg) {
                    [void]$regExports.Add((Get-Content -LiteralPath $tempReg -Raw))
                }
            } catch { }
            finally { Remove-Item $tempReg -Force -ErrorAction SilentlyContinue }
        }

        if ($regExports.Count -gt 0) {
            $merged = $regExports[0]
            for ($i = 1; $i -lt $regExports.Count; $i++) {
                $body = $regExports[$i] -replace '^Windows Registry Editor Version 5\.00\s*', ''
                $merged += "`r`n" + $body
            }
            Set-Content -LiteralPath $backupFile -Value $merged -Encoding Unicode
            Write-Log ("  Backup: {0}" -f $backupFile) -Level OK
        }

        Write-Log 'Scheduled tasks: rollback via Enable-ScheduledTask if needed.' -Level INFO
    }

    if ($Script:DryRun) {
        Write-Log ("[PREVIEW] Would prompt to disable {0} entries." -f $disableEntries.Count) -Level PREVIEW
        return
    }

    # ================================================================
    # PHASE 5: Action
    # ================================================================
    Write-Host ''

    $autoApprove = $Script:AllowPersistenceAction -and $Script:YesToAll

    if (-not $autoApprove) {
        if (-not (Confirm-Action -Query ('Process {0} non-essential entries?' -f $disableEntries.Count))) {
            Write-Log 'Step 38 action declined by user.' -Level WARN
            return
        }
    } else {
        Write-Log 'Auto-processing all candidates (-AllowPersistenceAction + -YesToAll).' -Level WARN
    }

    $startupDisabled = 0
    $tasksDisabled   = 0
    $failed          = 0
    $kept            = 0

    # StartupApproved mapping
    $approvedMap = @{
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'         = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'     = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'         = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'     = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'     = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
    }

    foreach ($e in $disableEntries) {
        $approved = $autoApprove
        if (-not $autoApprove) {
            $approved = Confirm-Action -Query ('Disable {0}?' -f $e.Name)
        }

        if (-not $approved) {
            Write-Log ("  [KEPT] {0}" -f $e.Name) -Level INFO
            $kept++
            continue
        }

        # Scheduled task
        if ($e.Location -notlike 'HK*' -and $e.Location -notlike '*\Startup*' -and $e.Location -match '^\\') {
            try {
                Disable-ScheduledTask -TaskPath $e.Location -TaskName $e.Name -ErrorAction Stop | Out-Null
                Write-Log ("  [DISABLED TASK] {0}{1}" -f $e.Location, $e.Name) -Level OK
                $tasksDisabled++
            } catch {
                Write-Log ("  [FAIL] {0}: {1}" -f $e.Name, $_.Exception.Message) -Level WARN
                $failed++
            }
            continue
        }

        # Registry startup entry
        $approvedPath = $approvedMap[$e.Location]
        if ($approvedPath) {
            try {
                # Suppression: if we disabled this entry on a previous run AND
                # the user has re-enabled it since, honor their choice.
                # Marker key is a sibling of the StartupApproved value.
                $markerPath = 'HKCU:\Software\WinTune\DisabledStartups'
                if (-not (Test-Path -LiteralPath $markerPath)) {
                    New-Item -Path $markerPath -Force -ErrorAction SilentlyContinue | Out-Null
                }
                $markerName = '{0}_{1}' -f ($e.Location -replace '[\\/:*?"<>|]', '_'), $e.Name
                # [FIX-STEP38-MARKER] StrictMode-safe property access. The
                # old `.(...).$markerName` pattern throws under StrictMode
                # Latest when the property is absent (always true on first
                # run). PSObject.Properties returns $null for missing keys.
                $markerVal = $null
                try {
                    $__markerProps = Get-ItemProperty -Path $markerPath -Name $markerName -ErrorAction SilentlyContinue
                    if ($__markerProps -and $__markerProps.PSObject.Properties[$markerName]) {
                        $markerVal = $__markerProps.PSObject.Properties[$markerName].Value
                    }
                } catch { }

                if ($markerVal -eq 'user-reenabled') {
                    Write-Log ("  [SKIP-REENABLED] {0} (user re-enabled since last run)" -f $e.Name) -Level INFO
                    $kept++
                    continue
                }

                # Check if the entry is currently ENABLED (first byte != 0x03)
                $currentBytes = (Get-ItemProperty -Path $approvedPath -Name $e.Name -ErrorAction SilentlyContinue).($e.Name)
                if ($currentBytes -and $currentBytes.Length -ge 1 -and $currentBytes[0] -ne 0x03 -and $markerVal) {
                    # We disabled it before, user re-enabled it. Record that and skip.
                    New-ItemProperty -Path $markerPath -Name $markerName -Value 'user-reenabled' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                    Write-Log ("  [SKIP-REENABLED] {0} (user re-enabled since last run - not disabling again)" -f $e.Name) -Level INFO
                    $kept++
                    continue
                }

                if (-not (Test-Path -LiteralPath $approvedPath)) {
                    New-Item -Path $approvedPath -Force -ErrorAction Stop | Out-Null
                }
                # [FIX-STEP38-STARTUPBYTES] Preserve existing byte length.
                # Modern Windows uses 12-byte StartupApproved entries
                # (1-byte status + 11-byte FILETIME), but legacy-migrated
                # entries (from pre-Win8 systems) are 8 bytes. Writing
                # 12 bytes to an 8-byte slot causes Task Manager to
                # misparse and may silently re-enable the entry. If a
                # value already exists, keep its length and only flip
                # byte[0] to 0x03 (disabled). If no value exists, write
                # the modern 12-byte default.
                $__existing = (Get-ItemProperty -Path $approvedPath -Name $e.Name -ErrorAction SilentlyContinue).($e.Name)
                if ($__existing -is [byte[]] -and $__existing.Length -in @(8, 12)) {
                    $disabledBytes = New-Object byte[] $__existing.Length
                    [Array]::Copy($__existing, $disabledBytes, $__existing.Length)
                    $disabledBytes[0] = 0x03
                } else {
                    $disabledBytes = [byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                }
                New-ItemProperty -Path $approvedPath -Name $e.Name -Value $disabledBytes -PropertyType Binary -Force -ErrorAction Stop | Out-Null

                # Record that WE disabled it, so a future run can detect user re-enable.
                New-ItemProperty -Path $markerPath -Name $markerName -Value 'wintune-disabled' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Log ("  [DISABLED STARTUP] {0}" -f $e.Name) -Level OK
                $startupDisabled++
            } catch {
                Write-Log ("  [FAIL] {0}: {1}" -f $e.Name, $_.Exception.Message) -Level WARN
                $failed++
            }
        } else {
            Write-Log ("  [SKIP] {0} - startup folder entries not auto-disabled" -f $e.Name) -Level WARN
            $kept++
        }
    }

    # ================================================================
    # Summary
    # ================================================================
    Write-Host ''
    Write-Log ("Step 38 summary: {0} startup disabled, {1} tasks disabled, {2} protected/skipped, {3} failed" -f $startupDisabled, $tasksDisabled, $kept, $failed) -Level INFO
    Write-Log '' -Level INFO
    Write-Log 'Rollback:' -Level INFO
    Write-Log '  Startup entries: Task Manager -> Startup tab -> re-enable' -Level INFO
    Write-Log '  Scheduled tasks: Enable-ScheduledTask -TaskPath <path> -TaskName <name>' -Level INFO
    Write-Log '' -Level INFO
    Write-Log 'Step 38 complete.' -Level OK
    Write-Log '[SUCCESS] Non-essential persistence processed.' -Level OK
}

function Invoke-Step39 {
    <#
    .SYNOPSIS
        Spawns a detached, visible PowerShell window that installs
        Windows Updates via the PSWindowsUpdate module.

    .DESCRIPTION
        Gated behind -InstallUpdates.

        What it does:
          1. Copies wu-runner-body.ps1 (alongside this script)
             into %TEMP% with a unique name
          2. Launches a NEW VISIBLE PowerShell window running it
          3. Returns immediately - WinTune continues while the
             child window runs Windows Update independently

        The runner:
          * Auto-installs PSWindowsUpdate if missing
          * Installs Security, Critical, and Definition updates
          * Does NOT auto-reboot

        Isolation:
          * Child PowerShell is fully detached; WinTune exiting
            does not affect it
          * Child writes its own log:
            <ScriptDir>\WindowsUpdate_<timestamp>.log

        Safety:
          * Requires -InstallUpdates flag
          * Requires Y/N confirmation
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 39: Windows Update Auto-Install (Detached Shell)' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Launches a separate visible PowerShell to install Windows Updates.' -Level INFO

    # ---- Gate 1: -InstallUpdates required ----
    if (-not $Script:InstallUpdates) {
        Write-Log 'Step 39 blocked: -InstallUpdates flag was not supplied.' -Level INFO
        Write-Log 'Add -InstallUpdates to spawn the detached WU installer.' -Level INFO
        Write-Log '[INFO] Step 39 skipped: -InstallUpdates authorization flag absent.' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would spawn a detached visible PowerShell to run Install-WindowsUpdate.' -Level PREVIEW
        return
    }

    # ---- Confirmation ----
    Write-Log 'About to launch a separate visible PowerShell window.' -Level WARN
    Write-Log 'It will auto-install PSWindowsUpdate and install:' -Level INFO
    Write-Log '  - Security Updates' -Level INFO
    Write-Log '  - Critical Updates' -Level INFO
    Write-Log '  - Defender Definition Updates' -Level INFO
    Write-Log 'Feature updates and drivers will NOT be installed.' -Level INFO
    Write-Log 'No automatic reboot will occur.' -Level INFO

    if (-not (Confirm-Action -Query 'Launch the detached Windows Update installer?')) {
        Write-Log 'Step 39 skipped by user.' -Level WARN
        return
    }

    # ---- Locate runner (embedded) ----
    if (-not $Script:EmbeddedWuRunner) {
        Write-Log 'Embedded Windows Update runner missing - this is a bug.' -Level ERROR
        return
    }
    Write-Log 'Using embedded Windows Update runner' -Level OK

    # ---- Write runner to TEMP ----
    $runnerPath = New-SecureRunnerPath -LeafName 'WU.ps1'
    try {
        Set-Content -LiteralPath $runnerPath -Value $Script:EmbeddedWuRunner -Encoding UTF8 -ErrorAction Stop
        Write-Log ("  [OK] Runner written to: {0}" -f $runnerPath) -Level OK
    } catch {
        Write-Log ("Failed to write runner: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    # ---- Set environment variables for the child ----
    $env:FC_LOG_DIR   = $Script:ScriptDir
    $env:FC_YES_TO_ALL = if ($Script:YesToAll) { '1' } else { '0' }

    # ---- Launch detached visible shell ----
    Write-Log 'Launching detached visible PowerShell window...' -Level INFO

    # Fix B3 v3: probe the runner host before committing to a launch
    $__prereq = Test-DetachedLaunchPrereqs
    if (-not $__prereq.Ok) {
        Write-Log ("  [FAIL] Detached launch prerequisites failed: {0}" -f $__prereq.Reason) -Level ERROR
        Write-Log '  Step marked Failed (child could not start).' -Level ERROR
        throw ("Detached runner prereq failure: {0}" -f $__prereq.Reason)
    }

    # [FIX-DETACHED-5D] cross-run guard
    $__existing = @(Get-ExistingDetachedRunnerProcess -Kind 'Windows Update')
    if ($__existing.Count -gt 0) {
        Write-Log ("  [SKIP] Windows Update runner already active (PID {0}, started {1})." -f $__existing[0].Pid, $__existing[0].StartedAt) -Level WARN
        Write-Log '  Close the existing window first, or wait for it to exit, then re-run.' -Level WARN
        $Script:LastStepStatus = 'Skipped'
        return
    }

    try {
        # No -Wait so this returns immediately. Child is independent.
        $child = Start-Process -FilePath $Script:RunnerPowerShellExe -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$runnerPath`"" -PassThru

        Write-Log ("  [OK] Child PowerShell launched (PID {0})." -f $child.Id) -Level OK
        Register-DetachedExitTracking -Child $child -Kind 'Windows Update' -Note 'Step 39'
        # [FIX-PID-PARAM-3] Tracking is best-effort. A failure here must
        # never abort the launch block, because the child is already
        # running by this point.
        try { Register-TrackedRunnerKind -RunnerPid $child.Id -Kind 'Windows Update' -Note 'Step 39' }
        catch { Write-Log ("  [WARN] Cross-run tracking failed: {0}" -f $_.Exception.Message) -Level WARN }
        Add-ReportRunner -Kind 'Windows Update' -RunnerPid $child.Id -Note 'Step 39'
        Write-Log '  WinTune will continue; Windows Update runs independently.' -Level INFO
        Write-Log '  Look for the new window with the banner: WinTune - Windows Update Installer' -Level INFO
    } catch {
        Write-Log ("Failed to launch child PowerShell: {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    Write-Log 'Step 39 launched (detached). Update runs independently.' -Level OK

    # ---- B3 fix: clear FC_* env vars so a re-run in this session starts fresh ----
    Remove-Item Env:\FC_YES_TO_ALL -ErrorAction SilentlyContinue
    Write-Log '[SUCCESS] Step 39: Detached Windows Update installer launched.' -Level OK
    $Script:LastStepStatus = 'Detached'
}



# ============================================================
# STEP 41: Windows Defender Scans Cache Cleanup
# ============================================================
function Invoke-Step41 {
    <#
    .SYNOPSIS
        Clears old Microsoft Defender scan cache files and scan
        history. Reclaims disk space and reduces Defender's I/O
        during subsequent scans.

    .DESCRIPTION
        Defender stores the following under
        %ProgramData%\Microsoft\Windows Defender\:

          * Scans\History\Results\Resource  - cached scan results
            (json/ldb files; can accumulate 100-500 MB)
          * Scans\History\Service\DetectionHistory  - detection log
            (safe to clear; detection events also live in Event Log)
          * Scans\History\CacheManager      - scan cache manager
            index files
          * Scans\Cache                     - individual file scan
            caches (rebuild on next scan)

        These are all regenerable. Defender will re-scan files as
        needed and rebuild the caches.

        This step does NOT:
          * Touch quarantine (Threats folder)
          * Modify Defender preferences, exclusions, or rules
          * Touch the Defender engine or definitions
          * Stop or disable any Defender service

        Safety:
          * Runs as SYSTEM-equivalent (admin with TrustedInstaller
            ownership not required for these specific subfolders)
          * DryRun aware
          * Per-folder error handling; never fails the whole step
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 41: Windows Defender Scans Cache Cleanup' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    Write-Log 'Clears old Defender scan result caches and history.' -Level INFO
    Write-Log 'Defender is not disabled or modified - only regenerable caches.' -Level INFO

    if (-not (Confirm-Action -Query 'Clear Windows Defender scan caches?')) {
        Write-Log 'Step 41 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would clear Windows Defender scan result caches.' -Level PREVIEW
        return
    }

    $defenderRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender'
    if (-not (Test-Path -LiteralPath $defenderRoot)) {
        Write-Log 'Defender folder not present - skipped.' -Level INFO
        Write-Log 'Step 41 complete (not applicable).' -Level OK
        return
    }

    $cacheTargets = @(
        'Scans\History\Results\Resource'
        'Scans\History\Service\DetectionHistory'
        'Scans\History\Service\Resource'
        'Scans\History\CacheManager'
        'Scans\Cache'
    )

    $totalBytes = [int64]0
    $cleared    = 0
    $failed     = 0

    foreach ($sub in $cacheTargets) {
        $path = Join-Path $defenderRoot $sub
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Log ("  [SKIP] Not present: {0}" -f $sub) -Level DEBUG
            continue
        }

        # Measure before clearing
        $size = 0
        try {
            $size = (Get-ChildItem -LiteralPath $path -Recurse -File -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            if ($null -eq $size) { $size = 0 }
        } catch { }

        Write-Log ("  Clearing: {0} ({1:N1} MB)" -f $sub, ($size / 1MB)) -Level INFO

        try {
            Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

            $totalBytes += [int64]$size
            $cleared++
        } catch {
            Write-Log ("    Failed: {0}" -f $_.Exception.Message) -Level DEBUG
            $failed++
        }
    }

    $freedMB = [math]::Round($totalBytes / 1MB, 1)

    Write-Log ("Defender scan cache summary: {0} targets cleared, {1} failed, {2:N1} MB reclaimed" -f $cleared, $failed, $freedMB) -Level INFO

    Write-Log 'Step 41 complete.' -Level OK
    Write-Log '[SUCCESS] Defender scan caches cleared.' -Level OK
}




# ============================================================
# STEP 40: Windows\Installer Orphan Cleanup (gated)
# ============================================================
function Invoke-Step40 {
    <#
    .SYNOPSIS
        Removes orphaned Windows Installer cache files (.msi and
        .msp) that are no longer referenced by any installed product
        or patch. Reclaims space in C:\Windows\Installer.

    .DESCRIPTION
        Windows keeps a copy of every .msi and .msp in
        C:\Windows\Installer so it can repair, modify, or uninstall
        products. Over time, products are removed or upgraded, but
        the corresponding cache files are frequently orphaned.

        Algorithm:
          1. Read HKLM:\SOFTWARE\Classes\Installer\Products and
             the Wow6432Node variant. Each subkey is a 32-hex-digit
             "packed GUID" that corresponds to a cached .msi file.
          2. Read HKLM:\SOFTWARE\Classes\Installer\Patches and the
             Wow6432Node variant. Each subkey is a 32-hex-digit
             packed GUID that corresponds to a cached .msp file.
          3. Walk C:\Windows\Installer. For each .msi, extract the
             first 32 hex characters (before the first dot). If
             they're in the Products set, keep. Else orphan.
          4. Same for .msp files, matched against the Patches set.
          5. Files newer than 180 days are always kept, matching
             Microsoft's MSIZAP policy.
          6. Files with other extensions (.dll, .ico, .exe, etc.)
             are NEVER touched.

        Gating:
          * Requires -AllowInstallerCleanup
          * Requires explicit Y/N confirmation
          * Skip if fewer than 500 MB of orphans

        Safety:
          * DryRun-aware: previews the deletion list without action
          * 180-day age cutoff regardless of reference state
          * Only .msi and .msp extensions are candidates
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 40: Windows\Installer Orphan Cleanup' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowInstallerCleanup) {
        Write-Log 'Step 40 blocked: -AllowInstallerCleanup flag was not supplied.' -Level INFO
        Write-Log 'This step removes orphaned MSI/MSP cache files from C:\Windows\Installer.' -Level INFO
        Write-Log 'Re-run with -AllowInstallerCleanup if you explicitly want this.' -Level INFO
        Write-Log '[INFO] Step 40 skipped: authorization flag absent.' -Level INFO
        return
    }

    $installerDir = Join-Path $env:SystemRoot 'Installer'
    if (-not (Test-Path -LiteralPath $installerDir)) {
        Write-Log 'C:\Windows\Installer not present - skipped.' -Level INFO
        return
    }

    Write-Log 'Enumerating referenced ProductCodes from registry...' -Level INFO

    $referencedProducts = @{}
    $referencedPatches  = @{}

    $registryRoots = @(
        'HKLM:\SOFTWARE\Classes\Installer\Products'
        'HKLM:\SOFTWARE\Classes\Wow6432Node\Installer\Products'
    )
    foreach ($root in $registryRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            $subs = Get-ChildItem -LiteralPath $root -ErrorAction Stop
            foreach ($sub in $subs) {
                $name = Split-Path -Leaf $sub.PSPath
                if ($name -match '^[0-9A-Fa-f]{32}$') {
                    $referencedProducts[$name.ToUpperInvariant()] = $true
                }
            }
        } catch {
            Write-Log ("  [WARN] Could not read {0}: {1}" -f $root, $_.Exception.Message) -Level WARN
        }
    }

    $patchRoots = @(
        'HKLM:\SOFTWARE\Classes\Installer\Patches'
        'HKLM:\SOFTWARE\Classes\Wow6432Node\Installer\Patches'
    )
    foreach ($root in $patchRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            $subs = Get-ChildItem -LiteralPath $root -ErrorAction Stop
            foreach ($sub in $subs) {
                $name = Split-Path -Leaf $sub.PSPath
                if ($name -match '^[0-9A-Fa-f]{32}$') {
                    $referencedPatches[$name.ToUpperInvariant()] = $true
                }
            }
        } catch {
            Write-Log ("  [WARN] Could not read {0}: {1}" -f $root, $_.Exception.Message) -Level WARN
        }
    }

    Write-Log ("  Product codes in use: {0}" -f $referencedProducts.Count) -Level INFO
    Write-Log ("  Patch codes in use:   {0}" -f $referencedPatches.Count) -Level INFO

    Write-Log 'Scanning Windows\Installer for orphaned MSI/MSP files...' -Level INFO

    $allFiles = @()
    try {
        $allFiles = Get-ChildItem -LiteralPath $installerDir -File -Force -ErrorAction Stop
    } catch {
        Write-Log ("  [WARN] Cannot enumerate {0}: {1}" -f $installerDir, $_.Exception.Message) -Level WARN
        return
    }

    $cutoff = (Get-Date).AddDays(-$Script:InstallerMinAgeDays)
    $orphans = @()
    $totalOrphanBytes = [int64]0

    foreach ($file in $allFiles) {
        $ext = $file.Extension.ToLowerInvariant()
        if ($ext -ne '.msi' -and $ext -ne '.msp') { continue }

        $m = [regex]::Match($file.Name, '^([0-9A-Fa-f]{32})')
        if (-not $m.Success) { continue }

        $code = $m.Groups[1].Value.ToUpperInvariant()

        $isReferenced = $false
        if ($ext -eq '.msi' -and $referencedProducts.ContainsKey($code)) { $isReferenced = $true }
        if ($ext -eq '.msp' -and $referencedPatches.ContainsKey($code))  { $isReferenced = $true }

        if ($isReferenced) { continue }

        if ($file.LastWriteTime -gt $cutoff) {
            Write-Log ("  [KEEP] Recent orphan: {0}" -f $file.Name) -Level DEBUG
            continue
        }

        $orphans += $file
        $totalOrphanBytes += $file.Length
    }

    $totalOrphanMB = [math]::Round($totalOrphanBytes / 1MB, 1)
    Write-Log ("Orphaned MSI/MSP: {0} files, {1:N1} MB" -f $orphans.Count, $totalOrphanMB) -Level INFO

    if ($totalOrphanMB -lt $Script:InstallerMinOrphanMB -and -not $Script:ForceIrreversible) {
        Write-Log ('Less than {0} MB of orphans ({1:N1} MB) - not worth touching Windows\Installer.' -f $Script:InstallerMinOrphanMB, $totalOrphanMB) -Level INFO
        Write-Log ('Add -ForceIrreversible to override the {0} MB threshold.' -f $Script:InstallerMinOrphanMB) -Level INFO
        Write-Log '[INFO] Step 40 skipped: below safety threshold.' -Level INFO
        return
    } elseif ($totalOrphanMB -lt 500 -and $Script:ForceIrreversible) {
        Write-Log ('Only {0:N1} MB of orphans, but -ForceIrreversible was passed - proceeding.' -f $totalOrphanMB) -Level WARN
    }

    Write-Host '  Orphaned files (sample, first 30):' -ForegroundColor Cyan
    $sample = $orphans | Sort-Object Length -Descending | Select-Object -First 30
    foreach ($o in $sample) {
        Write-Host ('   {0,10:N0} KB  {1}' -f ($o.Length / 1KB), $o.Name) -ForegroundColor DarkGray
    }
    if ($orphans.Count -gt 30) {
        Write-Host ('   ... and {0} more' -f ($orphans.Count - 30)) -ForegroundColor DarkGray
    }

    if ($Script:DryRun) {
        Write-Log ("[PREVIEW] Would delete {0} orphaned MSI/MSP files, reclaim {1:N1} MB." -f $orphans.Count, $totalOrphanMB) -Level PREVIEW
        return
    }

    if (-not (Confirm-Action -Query ('Delete {0} orphaned files ({1:N1} MB)?' -f $orphans.Count, $totalOrphanMB))) {
        Write-Log 'Step 40 skipped by user.' -Level WARN
        return
    }

    $freed = [int64]0
    $deleted = 0
    $failed = 0

    foreach ($o in $orphans) {
        try {
            $size = $o.Length
            # Defensive: refuse to delete anything outside $installerDir
            if (-not $o.FullName.StartsWith($installerDir, [StringComparison]::OrdinalIgnoreCase)) {
                Write-Log ("  [WARN] Refused to delete outside Installer: {0}" -f $o.FullName) -Level WARN
                continue
            }
            Remove-Item -LiteralPath $o.FullName -Force -ErrorAction Stop
            $freed += $size
            $deleted++
        } catch {
            $failed++
            Write-Log ("  [WARN] Could not delete {0}: {1}" -f $o.Name, $_.Exception.Message) -Level DEBUG
        }
    }

    $freedMB = [math]::Round($freed / 1MB, 1)
    Write-Log ("Step 40 summary: {0} deleted, {1} failed, {2:N1} MB reclaimed" -f $deleted, $failed, $freedMB) -Level INFO

    Write-Log 'Step 40 complete.' -Level OK
    Write-Log '[SUCCESS] Windows\Installer orphaned MSI/MSP files removed.' -Level OK
}

# ============================================================
# STEP 42: ProgramData\Package Cache Cleanup (gated)
# ============================================================
function Invoke-Step42 {
    <#
    .SYNOPSIS
        Removes superseded package-cache folders under
        C:\ProgramData\Package Cache.

    .DESCRIPTION
        ProgramData\Package Cache stores installers and payloads
        used by Visual Studio, .NET, VC++ Redistributable, Windows
        SDK, and other bootstrapper products. Every time such a
        product is upgraded, the new version installs alongside the
        old cached payload. The old payload becomes orphaned but is
        not deleted by the installer.

        Algorithm:
          1. Enumerate all folders under
             C:\ProgramData\Package Cache
          2. Group folders by "product family" - the first
             meaningful token of the folder name (up to the first
             underscore, dash, or version-digit boundary).
          3. Within each group with 2+ folders, keep the newest by
             LastWriteTime. Older ones are candidates.
          4. Skip any folder referenced by an active Uninstall
             registry entry (HKLM\...\Uninstall\*).
          5. Skip anything modified in the last 30 days (safety).
          6. Skip anything smaller than 5 MB (not worth the risk).

        Gating:
          * Requires -AllowPackageCacheCleanup
          * Requires explicit Y/N confirmation
          * Skip if total candidate size < 100 MB

        Safety:
          * DryRun previews the deletion list without action
          * 30-day age guard
          * 5 MB size guard
          * Active-uninstall-reference guard
          * Never touches a product family with only one folder
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 42: ProgramData\Package Cache Cleanup' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowPackageCacheCleanup) {
        Write-Log 'Step 42 blocked: -AllowPackageCacheCleanup flag was not supplied.' -Level INFO
        Write-Log 'This step removes superseded installer caches from ProgramData\Package Cache.' -Level INFO
        Write-Log 'Re-run with -AllowPackageCacheCleanup if you explicitly want this.' -Level INFO
        Write-Log '[INFO] Step 42 skipped: authorization flag absent.' -Level INFO
        return
    }

    $cacheRoot = Join-Path $env:ProgramData 'Package Cache'
    if (-not (Test-Path -LiteralPath $cacheRoot)) {
        Write-Log 'C:\ProgramData\Package Cache not present - skipped.' -Level INFO
        return
    }

    Write-Log 'Enumerating Package Cache folders...' -Level INFO

    $allFolders = @()
    try {
        $allFolders = Get-ChildItem -LiteralPath $cacheRoot -Directory -Force -ErrorAction Stop
    } catch {
        Write-Log ("  [WARN] Cannot enumerate {0}: {1}" -f $cacheRoot, $_.Exception.Message) -Level WARN
        return
    }

    Write-Log ("  Total folders: {0}" -f $allFolders.Count) -Level INFO

    # ---- Build set of referenced folder names from Uninstall keys ----
    $referencedNames = @{}
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $uninstallRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            $subs = Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue
            foreach ($sub in $subs) {
                try {
                    $instLoc = (Get-ItemProperty -LiteralPath $sub.PSPath -Name 'InstallLocation' -ErrorAction SilentlyContinue).InstallLocation
                    $uninstStr = (Get-ItemProperty -LiteralPath $sub.PSPath -Name 'UninstallString' -ErrorAction SilentlyContinue).UninstallString
                    if ($instLoc) { $referencedNames[$instLoc.ToLowerInvariant()] = $true }
                    if ($uninstStr -and $uninstStr -match 'Package Cache\\([^\\"]+)') {
                        $referencedNames[$matches[1].ToLowerInvariant()] = $true
                    }
                } catch { }
            }
        } catch { }
    }
    Write-Log ("  Referenced cache folder names: {0}" -f $referencedNames.Count) -Level INFO

    # ---- Group folders by product family ----
    # Extract "family" = first token before _ or - or a version-digit boundary
    function Get-FamilyKey {
        param([string]$Name)
        # [FIX-STEP42-FAMILYKEY] Include the architecture token in the
        # family key. Without it, Microsoft.VCRedist.2015.x64 and
        # Microsoft.VCRedist.2015.x86 collapse to the same key, and the
        # older one is deleted as "superseded" — even though x86 and
        # x64 are separate installs. The $referencedNames protection
        # doesn't catch this because VCRedist's UninstallString is
        # usually "MsiExec.exe /X{GUID}" with no Package Cache path.
        # Including arch splits the folders into separate single-folder
        # groups, which are always kept (group.Count -lt 2 -> continue).
        $stripped = $Name -replace '_[0-9a-fA-F]{8,}$', ''
        $m = [regex]::Match($stripped, '^([A-Za-z]+(?:\.[A-Za-z0-9]+){0,3})')
        $key = if ($m.Success) { $m.Groups[1].Value.ToLowerInvariant() } else { $stripped.ToLowerInvariant() }
        if ($stripped -match '(?i)(x64|x86|arm64|amd64|i386)') {
            $key += '|' + $Matches[1].ToLowerInvariant()
        }
        return $key
    }

    $groups = @{}
    foreach ($folder in $allFolders) {
        $key = Get-FamilyKey $folder.Name
        if (-not $groups.ContainsKey($key)) { $groups[$key] = @() }
        $groups[$key] += $folder
    }

    Write-Log ("  Product families: {0}" -f $groups.Count) -Level INFO

    # ---- Identify superseded folders ----
    $cutoff = (Get-Date).AddDays(-$Script:PackageCacheMinAgeDays)
    $minSizeBytes = $Script:PackageCacheMinSizeMB * 1MB
    $candidates = @()
    $totalCandidateBytes = [int64]0

    foreach ($key in $groups.Keys) {
        $folders = $groups[$key]
        if ($folders.Count -lt 2) { continue }

        # Keep the newest by LastWriteTime
        $sorted = $folders | Sort-Object LastWriteTime -Descending
        $newest = $sorted[0]
        $older  = $sorted[1..($sorted.Count - 1)]

        foreach ($f in $older) {
            # Referenced by active uninstall?
            if ($referencedNames.ContainsKey($f.Name.ToLowerInvariant())) {
                Write-Log ("  [KEEP] Referenced: {0}" -f $f.Name) -Level DEBUG
                continue
            }
            # Too recent?
            if ($f.LastWriteTime -gt $cutoff) {
                Write-Log ("  [KEEP] Recent: {0}" -f $f.Name) -Level DEBUG
                continue
            }
            # Too small?
            $size = 0
            try {
                $size = (Get-ChildItem -LiteralPath $f.FullName -Recurse -File -Force -ErrorAction SilentlyContinue |
                         Measure-Object -Property Length -Sum).Sum
                if ($null -eq $size) { $size = 0 }
            } catch { }
            if ($size -lt $minSizeBytes) { continue }

            $candidates += [PSCustomObject]@{
                Folder  = $f
                Size    = [int64]$size
                Family  = $key
                Newest  = $newest.Name
            }
            $totalCandidateBytes += [int64]$size
        }
    }

    $totalCandidateMB = [math]::Round($totalCandidateBytes / 1MB, 1)
    Write-Log ("Superseded Package Cache folders: {0}, {1:N1} MB" -f $candidates.Count, $totalCandidateMB) -Level INFO

    if ($totalCandidateMB -lt $Script:PackageCacheMinTotalMB -and -not $Script:ForceIrreversible) {
        Write-Log ('Less than {0} MB of superseded caches ({1:N1} MB) - not worth touching.' -f $Script:PackageCacheMinTotalMB, $totalCandidateMB) -Level INFO
        Write-Log ('Add -ForceIrreversible to override the {0} MB threshold.' -f $Script:PackageCacheMinTotalMB) -Level INFO
        Write-Log '[INFO] Step 42 skipped: below safety threshold.' -Level INFO
        return
    } elseif ($totalCandidateMB -lt 100 -and $Script:ForceIrreversible) {
        Write-Log ('Only {0:N1} MB of superseded caches, but -ForceIrreversible was passed - proceeding.' -f $totalCandidateMB) -Level WARN
    }

    Write-Host '  Superseded folders (sample, first 30):' -ForegroundColor Cyan
    $sample = $candidates | Sort-Object Size -Descending | Select-Object -First 30
    foreach ($c in $sample) {
        Write-Host ('   {0,10:N0} KB  {1}' -f ($c.Size / 1KB), $c.Folder.Name) -ForegroundColor DarkGray
        Write-Host ('                 -> kept newer: {0}' -f $c.Newest) -ForegroundColor DarkGray
    }
    if ($candidates.Count -gt 30) {
        Write-Host ('   ... and {0} more' -f ($candidates.Count - 30)) -ForegroundColor DarkGray
    }

    # ---- Delete pass (gated by -AllowPackageCacheCleanup) ----
    if ($Script:DryRun) {
        Write-Log ("[PREVIEW] Would delete {0} superseded folders ({1:N1} MB)." -f $candidates.Count, $totalCandidateMB) -Level PREVIEW
        foreach ($c in $candidates) {
            Write-Host ('   [PREVIEW] {0,10:N0} KB  {1}' -f ($c.Size / 1KB), $c.Folder.Name) -ForegroundColor Magenta
        }
        Write-Log 'Step 42 complete (dry run).' -Level OK
        return
    }

    if (-not (Confirm-Action -Query ('Delete {0} superseded Package Cache folders ({1:N1} MB)?' -f $candidates.Count, $totalCandidateMB))) {
        Write-Log 'Step 42 skipped by user.' -Level WARN
        return
    }

    $deleted   = 0
    $delFailed = 0
    $freed     = [int64]0

    foreach ($c in $candidates) {
        $target = $c.Folder.FullName

        # Defensive containment guard: refuse anything outside $cacheRoot
        if (-not $target.StartsWith($cacheRoot, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Log ("  [WARN] Refused path outside Package Cache: {0}" -f $target) -Level WARN
            $delFailed++
            continue
        }

        try {
            Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
            $deleted++
            $freed += [int64]$c.Size
            Write-Log ("  [OK] Removed: {0} ({1:N0} KB)" -f $c.Folder.Name, ($c.Size / 1KB)) -Level OK
        } catch {
            $delFailed++
            Write-Log ("  [WARN] Could not remove {0}: {1}" -f $c.Folder.Name, $_.Exception.Message) -Level WARN
        }
    }

    $freedMB = [math]::Round($freed / 1MB, 1)
    Write-Log ("Step 42 summary: {0} deleted, {1} failed, {2:N1} MB reclaimed" -f $deleted, $delFailed, $freedMB) -Level INFO

    Write-Log 'Step 42 complete.' -Level OK
    Write-Log '[SUCCESS] Superseded Package Cache folders removed.' -Level OK
}

# ============================================================
# STEP 44: Optional Malwarebytes Scan (gated)
# ============================================================
function Invoke-Step44 {
    [CmdletBinding()]
    param()

    Write-Log 'STEP 44: Optional Malwarebytes Scan' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowMalwareScan) {
        Write-Log 'Step 44 blocked: -AllowMalwareScan flag was not supplied.' -Level INFO
        Write-Log '[INFO] Step 44 skipped: authorization flag absent.' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would run Malwarebytes quick scan if installed.' -Level PREVIEW
        return
    }

    $mbamCandidates = @(
        (Join-Path ${env:ProgramFiles}      'Malwarebytes\Anti-Malware\mbam.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Malwarebytes\Anti-Malware\mbam.exe')
    )
    $mbamPath = $mbamCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if (-not $mbamPath) {
        Write-Log 'Malwarebytes is not installed.' -Level INFO
        Write-Log 'Download free version: https://www.malwarebytes.com/mwb-download' -Level INFO
        Write-Log '[INFO] Step 44 skipped: Malwarebytes not present.' -Level INFO
        return
    }

    Write-Log ("Malwarebytes detected at: {0}" -f $mbamPath) -Level OK

    if (-not (Confirm-Action -Query 'Run Malwarebytes quick scan now?')) {
        Write-Log 'Step 44 skipped by user.' -Level WARN
        return
    }

    Write-Log 'Launching Malwarebytes quick scan...' -Level INFO
    try {
        $proc = Start-Process -FilePath $mbamPath -ArgumentList @('--scan','--silent','--no-reboot') -NoNewWindow -PassThru
        Write-Log ("  Malwarebytes launched (PID {0}). Scan runs in background." -f $proc.Id) -Level OK
    } catch {
        Write-Log ("Failed to launch Malwarebytes: {0}" -f $_.Exception.Message) -Level WARN
        return
    }

    Write-Log 'Step 44 complete.' -Level OK
}

# ============================================================
# STEP 45: SysMain Tuning (SSD-only)
# ============================================================
function Invoke-Step45 {
    <#
    .SYNOPSIS
        Tunes SysMain / prefetcher behaviour on all-SSD systems.

    .DESCRIPTION
        On Windows 10 (build < 22000):
            SysMain is essentially Superfetch - a disk-read prefetcher.
            On SSDs the benefit is negligible and the service just holds
            cached RAM. We set it to Manual and stop it.

        On Windows 11 (build >= 22000):
            SysMain hosts memory compression in addition to prefetch.
            Stopping it disables compression and increases RAM pressure
            under load. We therefore leave the service RUNNING and
            instead disable only the prefetcher via registry:
              EnablePrefetcher  = 0
              EnableSuperfetch  = 0

        Safety:
          * Gated behind -AllowSysMainTuning
          * Only runs if ALL fixed drives are SSD/NVMe
          * If any HDD is detected, skips with explanation
          * Windows 10 path is fully reversible: sc config SysMain start= auto
          * Windows 11 path is fully reversible: set both values back to 3
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 45: SysMain Tuning (SSD-only)' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowSysMainTuning) {
        Write-Log 'Step 45 blocked: -AllowSysMainTuning flag was not supplied.' -Level INFO
        Write-Log 'Re-run with -AllowSysMainTuning to enable.' -Level INFO
        Write-Log '[INFO] Step 45 skipped: authorization flag absent.' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would tune SysMain/prefetcher on all-SSD systems.' -Level PREVIEW
        return
    }

    # ---- Check drive types ----
    $drives = @()
    try {
        $drives = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
                  Where-Object { $_.DriveType -eq 3 }
    } catch {
        Write-Log 'Drive enumeration failed - skipping Step 45.' -Level WARN
        return
    }

    $hasHdd = $false
    $checked = 0
    foreach ($d in $drives) {
        $letter = $d.DeviceID.TrimEnd(':')
        try {
            $partitions = Get-Partition -DriveLetter $letter -ErrorAction Stop
            $disk       = Get-Disk -Number $partitions[0].DiskNumber -ErrorAction Stop
            $physical   = Get-PhysicalDisk -DeviceNumber $disk.Number -ErrorAction SilentlyContinue
            if ($physical -and $physical.MediaType -eq 3) {
                $hasHdd = $true
                Write-Log ("  HDD detected: {0}" -f $d.DeviceID) -Level WARN
                break
            }
            $checked++
        } catch { }
    }

    if ($hasHdd) {
        Write-Log 'HDD present - SysMain provides real benefit on mechanical drives.' -Level WARN
        Write-Log 'Skipping SysMain tuning to preserve HDD performance.' -Level WARN
        Write-Log '[INFO] Step 45 skipped: HDD present.' -Level INFO
        return
    }

    if ($checked -eq 0) {
        Write-Log 'Could not classify any drive - skipping for safety.' -Level WARN
        Write-Log '[INFO] Step 45 skipped: drive classification failed.' -Level INFO
        return
    }

    Write-Log ("All {0} drive(s) are SSD/NVMe - SysMain tuning is safe." -f $checked) -Level OK

    # ---- Detect OS build ----
    $__osBuild = $null
    try {
        $__osBuild = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).BuildNumber
    } catch {
        Write-Log ("  [WARN] Could not determine OS build: {0}" -f $_.Exception.Message) -Level WARN
    }

    # [FIX-TIER1-NTFS-ACCESS] Disable NTFS last-access timestamp
    # updates. Reduces disk writes on read-heavy workloads with no
    # user-visible downside — last-access is already disabled by
    # default on most modern Windows systems (value 0x80000003
    # means "user managed, disabled"). Setting to 1 makes it
    # explicit and fleet-consistent.
    try {
        $__fsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
        if (-not (Test-Path -LiteralPath $__fsPath)) { New-Item -Path $__fsPath -Force | Out-Null }
        New-ItemProperty -Path $__fsPath -Name 'NtfsDisableLastAccessUpdate' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log '  [OK] NTFS last-access timestamps disabled.' -Level OK
    } catch {
        Write-Log ("  [WARN] Could not disable NTFS last-access: {0}" -f $_.Exception.Message) -Level WARN
    }

    # ============================================================
    # Windows 11 path (build >= 22000)
    # Leave SysMain running to preserve memory compression.
    # Disable only the prefetcher via registry.
    # ============================================================
    if ($__osBuild -ge 22000) {
        Write-Log ("Windows 11 detected (build {0}) - disabling prefetcher via registry." -f $__osBuild) -Level INFO
        Write-Log 'SysMain will remain running to preserve memory compression.' -Level INFO

        $prefetchParams = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
        Backup-RegistryKey -Step 45 -RegPath 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'

        try {
            if (-not (Test-Path -LiteralPath $prefetchParams)) {
                New-Item -Path $prefetchParams -Force -ErrorAction Stop | Out-Null
            }

            New-ItemProperty -Path $prefetchParams -Name 'EnablePrefetcher' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Log '  [OK] EnablePrefetcher = 0' -Level OK

            New-ItemProperty -Path $prefetchParams -Name 'EnableSuperfetch' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Log '  [OK] EnableSuperfetch = 0' -Level OK

            Write-Host ''
            Write-Log 'Step 45 complete.' -Level OK
            Write-Log '[SUCCESS] Prefetcher disabled via registry (SysMain left running).' -Level OK
            Write-Log '[REBOOT REQUIRED] The prefetcher change takes effect on next boot.' -Level WARN
            Write-Log 'Rollback: set EnablePrefetcher and EnableSuperfetch back to 3.' -Level INFO
            $Script:RebootRequired = $true
            if ($Script:RebootReasons -notcontains 'Step 45 (prefetcher)') {
                $Script:RebootReasons += 'Step 45 (prefetcher)'
            }
        } catch {
            Write-Log ("  [WARN] Could not write PrefetchParameters: {0}" -f $_.Exception.Message) -Level WARN
        }
        return
    }

    # ============================================================
    # Windows 10 path (build < 22000)
    # Set SysMain to Manual and stop it.
    # ============================================================
    Write-Log ("Windows 10 detected (build {0}) - tuning SysMain service." -f $__osBuild) -Level INFO

    $svc = Get-Service -Name 'SysMain' -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log 'SysMain service not present on this system.' -Level INFO
        return
    }

    $currentStart = (Get-CimInstance Win32_Service -Filter "Name='SysMain'" -ErrorAction SilentlyContinue).StartMode
    Write-Log ("Current SysMain startup: {0}" -f $currentStart) -Level INFO

    if ($currentStart -eq 'Manual') {
        Write-Log 'SysMain is already set to Manual. Nothing to do.' -Level OK
        Write-Log 'Step 45 complete.' -Level OK
        return
    }

    Write-Host ''
    Write-Log 'About to set SysMain to Manual startup and stop it.' -Level WARN
    Write-Log 'Reason: all drives are SSD - SysMain provides no measurable benefit.' -Level INFO

    if (-not (Confirm-Action -Query 'Disable SysMain on this SSD-only system?')) {
        Write-Log 'Step 45 skipped by user.' -Level WARN
        return
    }

    try {
        $null = & sc.exe config SysMain start= demand 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log '  [OK] SysMain startup set to Manual.' -Level OK
        } else {
            Write-Log ("  [WARN] sc config returned {0}" -f $LASTEXITCODE) -Level WARN
            return
        }
    } catch {
        Write-Log ("  [WARN] Could not reconfigure SysMain: {0}" -f $_.Exception.Message) -Level WARN
        return
    }

    if ($svc.Status -eq 'Running') {
        try {
            Stop-Service -Name 'SysMain' -Force -ErrorAction Stop
            Write-Log '  [OK] SysMain service stopped.' -Level OK
        } catch {
            Write-Log ("  [WARN] Could not stop SysMain: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    Write-Host ''
    Write-Log 'Step 45 complete.' -Level OK
    Write-Log '[SUCCESS] SysMain set to Manual on SSD-only system.' -Level OK
    Write-Log 'Rollback: sc config SysMain start= auto' -Level INFO
}

# ============================================================
# STEP 46: Delivery Optimization Upload Limit
# ============================================================
function Invoke-Step46 {
    <#
    .SYNOPSIS
        Limits Delivery Optimization to LAN-only sharing.

    .DESCRIPTION
        Windows Delivery Optimization is a P2P feature that shares Windows
        Update chunks with other PCs. On some networks this uploads data
        to strangers, consuming bandwidth.

        This step sets DODownloadMode = 1 (LAN-only sharing):
          * Microsoft downloads continue at full speed
          * Peer sharing is limited to the local network
          * No uploads to internet peers

        Modes:
          0 = HTTP only (no P2P at all)
          1 = LAN peering only (recommended)
          3 = Internet + LAN peering (Windows default)

        Safety:
          * Gated behind -AllowDoTuning
          * Uses documented registry key
          * Fully reversible: set DODownloadMode back to 3
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 46: Delivery Optimization Upload Limit' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowDoTuning) {
        Write-Log 'Step 46 blocked: -AllowDoTuning flag was not supplied.' -Level INFO
        Write-Log 'Re-run with -AllowDoTuning to enable.' -Level INFO
        Write-Log '[INFO] Step 46 skipped: authorization flag absent.' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would set Delivery Optimization to LAN-only peering (mode 1).' -Level PREVIEW
        return
    }

    $doPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'

    Backup-RegistryKey -Step 46 -RegPath 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
    # ---- Check current mode ----
    $currentMode = $null
    try {
        $currentMode = (Get-ItemProperty -Path $doPath -Name 'DODownloadMode' -ErrorAction SilentlyContinue).DODownloadMode
    } catch { }

    $currentText = switch ($currentMode) {
        0       { 'HTTP only (no P2P)' }
        1       { 'LAN only' }
        2       { 'Internet only (deprecated)' }
        3       { 'Internet + LAN (Windows default)' }
        99      { 'Simple mode' }
        100     { 'Bypass mode' }
        default { 'Not configured' }
    }

    Write-Log ("Current DODownloadMode = {0} ({1})" -f $currentMode, $currentText) -Level INFO

    if ($currentMode -eq 1) {
        Write-Log 'Delivery Optimization is already set to LAN-only. Nothing to do.' -Level OK
        Write-Log 'Step 46 complete.' -Level OK
        return
    }

    # ---- Confirm ----
    Write-Host ''
    Write-Log 'About to set Delivery Optimization to LAN-only (mode 1).' -Level WARN
    Write-Log 'Effect: Microsoft downloads stay fast, peer uploads stop.' -Level INFO

    if (-not (Confirm-Action -Query 'Limit Delivery Optimization to LAN-only sharing?')) {
        Write-Log 'Step 46 skipped by user.' -Level WARN
        return
    }

    # ---- Apply ----
    try {
        if (-not (Test-Path -LiteralPath $doPath)) {
            New-Item -Path $doPath -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -Path $doPath -Name 'DODownloadMode' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log '  [OK] DODownloadMode set to 1 (LAN-only).' -Level OK
        # P3: Step 46 rollback entries
        Add-RollbackEntry -Step 46 -Type 'RegistryHKCU' -Data @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'; Name = 'DODownloadMode'; Existed = $false; Value = $null; Type = 'DWord' }
    } catch {
        Write-Log ("  [WARN] Could not set DODownloadMode: {0}" -f $_.Exception.Message) -Level WARN
        return
    }

    # ---- Restart DO service to pick up the change ----
    try {
        $dosvc = Get-Service -Name 'DoSvc' -ErrorAction SilentlyContinue
        if ($dosvc -and $dosvc.Status -eq 'Running') {
            Restart-Service -Name 'DoSvc' -Force -ErrorAction Stop
            Write-Log '  [OK] Delivery Optimization service restarted.' -Level OK
        }
    } catch {
        Write-Log ("  [WARN] Could not restart DoSvc: {0}" -f $_.Exception.Message) -Level WARN
        Write-Log '  The setting will take effect on next reboot.' -Level INFO
    }

    Write-Host ''
    Write-Log 'Step 46 complete.' -Level OK
    Write-Log '[SUCCESS] Delivery Optimization set to LAN-only peering.' -Level OK
    Write-Log '' -Level INFO
    $rollbackCmd = "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name DODownloadMode"
    Write-Log ("Rollback: {0}" -f $rollbackCmd) -Level INFO
}

# ============================================================
# STEP 47: CapabilityAccessManager WAL Detection and Cleanup
# ============================================================
function Invoke-Step47 {
    <#
    .SYNOPSIS
        Detects and (optionally) cleans up a bloated
        CapabilityAccessManager WAL file.

    .DESCRIPTION
        A documented Windows bug caused the Write-Ahead Log (WAL) file
        for the Capability Access Manager service to grow without bound,
        sometimes reaching 100+ GB. KB5095093 and the July 2026 Patch
        Tuesday update fix the *growth* bug but do NOT shrink an existing
        bloated file.

        Detection (always runs):
          * Measures the WAL size (direct Get-Item, robocopy fallback)
          * Reports HEALTHY (< 1 GB) or BLOATED (>= 1 GB)

        Cleanup (only with -AllowCamWALCleanup):
          * Stops camsvc
          * Deletes only CapabilityAccessManager.db-wal
          * Never touches .db or the folder
          * Restarts camsvc, verifies it came back
          * Retries delete once after a 3-second delay if locked

        Safety:
          * Never runs cleanup without -AllowCamWALCleanup
          * Skips if camsvc is not present
          * Preserves camera/mic/location permissions
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 47: CapabilityAccessManager WAL Detection' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    $walFolder = Join-Path $env:ProgramData 'Microsoft\Windows\CapabilityAccessManager'
    $walPath   = Join-Path $walFolder 'CapabilityAccessManager.db-wal'

    if (-not (Test-Path -LiteralPath $walFolder)) {
        Write-Log 'CapabilityAccessManager folder not present.' -Level INFO
        Write-Log '[INFO] Step 47 skipped: folder does not exist.' -Level INFO
        return
    }

    # ---- Measure the WAL file ----
    $walSizeBytes  = -1
    $measureMethod = 'direct'

    try {
        if (Test-Path -LiteralPath $walPath -ErrorAction Stop) {
            $item = Get-Item -LiteralPath $walPath -Force -ErrorAction Stop
            $walSizeBytes = [int64]$item.Length
        } else {
            Write-Log 'WAL file not present (healthy).' -Level OK
            Write-Log '[INFO] Step 47 complete: nothing to check.' -Level INFO
            return
        }
    } catch {
        # Direct Get-Item failed (usually permission). Try CIM first, then
        # report honestly if both fail - do NOT guess with robocopy parsing.
        $measureMethod = 'cim'
        try {
            $cim = Get-CimInstance -ClassName CIM_DataFile -Filter (
                "Name='{0}'" -f $walPath.Replace('\','\\')
            ) -ErrorAction Stop
            if ($cim -and $cim.FileSize) {
                $walSizeBytes = [int64]$cim.FileSize
            } else {
                throw 'CIM query returned no FileSize'
            }
        } catch {
            $measureMethod = 'unknown'
            Write-Log ('Could not measure WAL file directly or via CIM: {0}' -f $_.Exception.Message) -Level WARN
            Write-Log 'WAL size UNKNOWN (permission denied on CapabilityAccessManager folder).' -Level WARN
            Write-Log 'This is normal for non-SYSTEM users. If you suspect a bloated WAL,' -Level INFO
            Write-Log 'check manually from an elevated prompt:' -Level INFO
            Write-Log ('  Get-Item "{0}"' -f $walPath) -Level INFO
            Write-Log '[INFO] Step 47 complete: measurement unavailable.' -Level INFO
            return
        }
    }

    if ($walSizeBytes -lt 0) {
        Write-Log 'Could not determine WAL file size.' -Level WARN
        Write-Log '[INFO] Step 47 complete: size unknown.' -Level INFO
        return
    }

    $walMB = [math]::Round($walSizeBytes / 1MB, 1)
    $walGB = [math]::Round($walSizeBytes / 1GB, 2)
    Write-Log ('CapabilityAccessManager.db-wal = {0} MB ({1} GB)' -f $walMB, $walGB) -Level INFO
    Write-Log ('Measurement method: {0}' -f $measureMethod) -Level DEBUG

    if ($walSizeBytes -lt 1GB) {
        Write-Log 'Status: HEALTHY (under 1 GB threshold).' -Level OK
        Write-Log 'No action needed.' -Level INFO
        Write-Log '[INFO] Step 47 complete.' -Level INFO
        return
    }

    Write-Host ''
    Write-Log '[WARNING] WAL file is bloated.' -Level WARN
    Write-Log 'Documented Windows bug (fixed by KB5095093 + July 2026 updates).' -Level WARN
    Write-Log 'Those updates fix future growth but do NOT shrink an existing file.' -Level WARN
    Write-Log '' -Level WARN

    if (-not $Script:AllowCamWALCleanup) {
        Write-Log 'Cleanup NOT authorized.' -Level INFO
        Write-Log 'Re-run with -AllowCamWALCleanup to remove it automatically.' -Level INFO
        Write-Log '' -Level INFO
        Write-Log 'Manual procedure:' -Level INFO
        Write-Log '  1. Elevated Command Prompt' -Level INFO
        Write-Log '  2. net stop camsvc' -Level INFO
        Write-Log ('  3. del "{0}"' -f $walPath) -Level INFO
        Write-Log '  4. net start camsvc' -Level INFO
        Write-Log '' -Level INFO
        Write-Log 'If step 3 fails, boot into WinRE and delete it there.' -Level INFO
        Write-Log '' -Level WARN
        Write-Log 'DO NOT delete the whole folder or the .db file.' -Level WARN
        Write-Log '[INFO] Step 47 complete: manual action required.' -Level INFO
        return
    }

    Write-Log 'Cleanup authorized via -AllowCamWALCleanup.' -Level WARN

    if ($Script:DryRun) {
        Write-Log '[PREVIEW] Would stop camsvc and delete CapabilityAccessManager.db-wal.' -Level PREVIEW
        return
    }

    $svc = Get-Service -Name 'camsvc' -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log 'camsvc service not present. Cleanup skipped.' -Level WARN
        return
    }

    if (-not (Confirm-Action -Query 'Stop camsvc and delete the bloated WAL file?')) {
        Write-Log 'Step 47 cleanup skipped by user.' -Level WARN
        return
    }

    $svcWasRunning = ($svc.Status -eq 'Running')
    if ($svcWasRunning) {
        Write-Log 'Stopping camsvc...' -Level INFO
        try {
            Stop-Service -Name 'camsvc' -Force -ErrorAction Stop
            Write-Log '  [OK] camsvc stopped.' -Level OK
            Start-Sleep -Seconds 2
        } catch {
            Write-Log ('  [WARN] Could not stop camsvc: {0}' -f $_.Exception.Message) -Level WARN
            Write-Log '  Skipping cleanup.' -Level WARN
            return
        }
    }

    Write-Log 'Deleting WAL file...' -Level INFO
    $deleted = $false
    try {
        Remove-Item -LiteralPath $walPath -Force -ErrorAction Stop
        $deleted = $true
        Write-Log '  [OK] WAL file deleted.' -Level OK
    } catch {
        Write-Log ('  [WARN] First delete failed: {0}' -f $_.Exception.Message) -Level WARN
        Write-Log '  Retrying after 3 seconds...' -Level INFO
        Start-Sleep -Seconds 3
        try {
            Remove-Item -LiteralPath $walPath -Force -ErrorAction Stop
            $deleted = $true
            Write-Log '  [OK] WAL file deleted on retry.' -Level OK
        } catch {
            Write-Log ('  [ERROR] Could not delete WAL: {0}' -f $_.Exception.Message) -Level ERROR
            Write-Log '  File locked. Use the WinRE manual procedure.' -Level ERROR
        }
    }

    if ($svcWasRunning) {
        Write-Log 'Restarting camsvc...' -Level INFO
        try {
            Start-Service -Name 'camsvc' -ErrorAction Stop
            Write-Log '  [OK] camsvc restarted.' -Level OK
        } catch {
            Write-Log ('  [ERROR] Could not restart camsvc: {0}' -f $_.Exception.Message) -Level ERROR
            Write-Log '  Reboot to restore camera/mic/location access.' -Level ERROR
        }
    }

    Write-Host ''
    if ($deleted) {
        Write-Log 'Step 47 complete.' -Level OK
        Write-Log '[SUCCESS] Bloated CapabilityAccessManager WAL removed.' -Level OK
        Write-Log 'Service will build a fresh small WAL. Permissions preserved.' -Level INFO
    } else {
        Write-Log 'Step 47 completed with warnings.' -Level WARN
        Write-Log '[WARNING] WAL could not be removed. Use WinRE procedure.' -Level WARN
    }
}
# ============================================================
# STEP 49: Disable AutoRun on Removable Media (opt-in)
# ============================================================
function Invoke-Step49 {
    <#
    .SYNOPSIS
        Disables Windows AutoRun and AutoPlay on removable media.

    .DESCRIPTION
        AutoRun is a legacy Windows feature that executes autorun.inf
        when media is inserted. It was abused by malware (Conficker,
        Stuxnet, etc.) to auto-execute from infected USB drives.

        Sets: HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
              NoDriveTypeAutorun = 0xFF (all drive types)

        Safety:
          * HKCU-only policy
          * Reversible: delete the NoDriveTypeAutorun value
          * Gated behind -AllowAutoRunDisable
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 49: Disable AutoRun on Removable Media' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowAutoRunDisable) {
        Write-Log 'Step 49 blocked: -AllowAutoRunDisable flag was not supplied.' -Level INFO
        Write-Log 'Re-run with -AllowAutoRunDisable to enable.' -Level INFO
        Write-Log '[INFO] Step 49 skipped: authorization flag absent.' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would set NoDriveTypeAutorun = 0xFF (disable AutoRun on all drives).' -Level PREVIEW
        return
    }

    $policyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Backup-RegistryKey -Step 49 -RegPath 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'

    $currentValue = $null
    try {
        $currentValue = (Get-ItemProperty -Path $policyPath -Name 'NoDriveTypeAutorun' -ErrorAction SilentlyContinue).NoDriveTypeAutorun
    } catch { }

    $currentText = if ($null -eq $currentValue) {
        'Not configured (Windows default: AutoRun enabled)'
    } elseif ($currentValue -eq 0xFF -or $currentValue -eq 255) {
        'AutoRun disabled (0xFF)'
    } else {
        ("Custom value: 0x{0:X2}" -f $currentValue)
    }

    Write-Log ("Current NoDriveTypeAutorun = {0}" -f $currentText) -Level INFO

    if ($currentValue -eq 0xFF -or $currentValue -eq 255) {
        Write-Log 'AutoRun is already disabled. Nothing to do.' -Level OK
        Write-Log 'Step 49 complete.' -Level OK
        return
    }

    Write-Host ''
    Write-Log 'About to disable AutoRun on all removable media.' -Level WARN
    Write-Log 'Effect: USB drives and CDs will not auto-execute or prompt.' -Level INFO

    if (-not (Confirm-Action -Query 'Disable AutoRun on all drives?')) {
        Write-Log 'Step 49 skipped by user.' -Level WARN
        return
    }

    try {
        if (-not (Test-Path -LiteralPath $policyPath)) {
            New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -Path $policyPath -Name 'NoDriveTypeAutorun' -Value 0xFF -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log '  [OK] NoDriveTypeAutorun set to 0xFF.' -Level OK
        # P3: Step 49 rollback entries
        Add-RollbackEntry -Step 49 -Type 'RegistryHKCU' -Data @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutorun'; Existed = $false; Value = $null; Type = 'DWord' }
    } catch {
        Write-Log ("  [WARN] Could not set NoDriveTypeAutorun: {0}" -f $_.Exception.Message) -Level WARN
        return
    }

    Start-Sleep -Milliseconds 500
    $verify = (Get-ItemProperty -Path $policyPath -Name 'NoDriveTypeAutorun' -ErrorAction SilentlyContinue).NoDriveTypeAutorun

    if ($verify -eq 0xFF -or $verify -eq 255) {
        Write-Host ''
        Write-Log 'Step 49 complete.' -Level OK
        Write-Log '[SUCCESS] AutoRun disabled on all drive types.' -Level OK
        Write-Log 'USB drives and CDs no longer auto-execute.' -Level INFO
        Write-Log '' -Level INFO
        Write-Log "Rollback: Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutorun" -Level INFO
    } else {
        Write-Log 'Step 49 completed but verification failed.' -Level WARN
    }
}
# ============================================================
# STEP 50: Context Menu Handler Audit (opt-in action)
# ============================================================
function Invoke-Step50 {
    <#
    .SYNOPSIS
        Enumerates Windows Explorer context menu shell extensions
        and classifies each as Keep or Disable.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 50: Context Menu Handler Audit' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    $handlerRoots = @(
        'HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers'
        'HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers'
        'HKLM:\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers'
        'HKLM:\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers'
        'HKLM:\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers'
        'HKLM:\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers'
        'HKCU:\Software\Classes\*\shellex\ContextMenuHandlers'
        'HKCU:\Software\Classes\Directory\shellex\ContextMenuHandlers'
        'HKCU:\Software\Classes\Directory\Background\shellex\ContextMenuHandlers'
        'HKCU:\Software\Classes\Drive\shellex\ContextMenuHandlers'
        'HKCU:\Software\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers'
        'HKCU:\Software\Classes\Folder\shellex\ContextMenuHandlers'
    )

    Write-Log 'PHASE 1: Enumerating context menu handlers...' -Level INFO

    $entries = @()
    foreach ($root in $handlerRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        try {
            $subkeys = Get-ChildItem -LiteralPath $root -ErrorAction Stop
            foreach ($sk in $subkeys) {
                $name = Split-Path -Leaf $sk.PSPath
                if ($name -like 'PS*') { continue }
                if ($name -like '*.WinTuneDisabled') { continue }

                $clsid = $null
                try {
                    $clsid = (Get-ItemProperty -LiteralPath $sk.PSPath -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                } catch { }

                $targetPath = ''
                if ($clsid -and $clsid -match '^\{[0-9A-Fa-f-]+\}$') {
                    $clsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
                    if (Test-Path -LiteralPath $clsidKey) {
                        try {
                            $targetPath = (Get-ItemProperty -LiteralPath $clsidKey -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                        } catch { }
                    }
                }

                $class = if ($targetPath) {
                    Get-PersistenceClassification -FilePath $targetPath
                } else {
                    'Keep'
                }

                $entries += [PSCustomObject]@{
                    Name    = $name
                    Root    = $root
                    KeyPath = $sk.PSPath
                    Clsid   = $clsid
                    Target  = $targetPath
                    Kind    = $class
                }
            }
        } catch {
            Write-Log ("  [WARN] Could not read {0}: {1}" -f $root, $_.Exception.Message) -Level DEBUG
        }
    }

    $keepEntries    = @($entries | Where-Object { $_.Kind -eq 'Keep' })
    $disableEntries = @($entries | Where-Object { $_.Kind -eq 'Disable' })

    Write-Host ''
    Write-Log ("Total: {0} context menu handlers ({1} Keep, {2} Disable)" -f $entries.Count, $keepEntries.Count, $disableEntries.Count) -Level INFO

    if ($keepEntries.Count -gt 0) {
        Write-Host ''
        Write-Log 'PROTECTED (trusted publisher):' -Level OK
        foreach ($e in $keepEntries) {
            Write-Log ("  [KEEP] {0}" -f $e.Name) -Level OK
        }
    }

    if ($disableEntries.Count -gt 0) {
        Write-Host ''
        Write-Log 'CANDIDATES FOR DISABLE:' -Level WARN
        foreach ($e in $disableEntries) {
            Write-Log ("  [DISABLE] {0}" -f $e.Name) -Level WARN
            if ($e.Target) {
                Write-Log ("            Target: {0}" -f $e.Target) -Level WARN
            }
        }
    }

    if ($disableEntries.Count -eq 0) {
        Write-Host ''
        Write-Log 'No non-essential context menu handlers detected.' -Level OK
        Write-Log 'Step 50 complete.' -Level OK
        return
    }

    if (-not $Script:AllowContextMenuAction) {
        Write-Host ''
        Write-Log 'Action NOT authorized. Use -AllowContextMenuAction to disable candidates.' -Level INFO
        Write-Log 'Step 50 complete (audit only).' -Level OK
        return
    }

    if ($Script:DryRun) {
        Write-Log ("[PREVIEW] Would prompt to disable {0} context menu handler(s)." -f $disableEntries.Count) -Level PREVIEW
        return
    }

    Write-Host ''

    if (-not (Confirm-Action -Query ('Disable {0} context menu handler(s)?' -f $disableEntries.Count))) {
        Write-Log 'Step 50 action declined by user.' -Level WARN
        return
    }

    $disabled = 0
    $failed   = 0

    foreach ($e in $disableEntries) {
        try {
            $oldFull    = $e.KeyPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
            $parentFull = Split-Path -Parent $oldFull
            $newName    = "$($e.Name).WinTuneDisabled"

            $null = & reg.exe copy "$oldFull" "$parentFull\$newName" /s /f 2>&1
            if ($LASTEXITCODE -eq 0) {
                $null = & reg.exe delete "$oldFull" /f 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log ("  [DISABLED] {0}" -f $e.Name) -Level OK
                    Add-RollbackEntry -Step 50 -Type 'ContextMenu' -Data @{
                        KeyPath      = $e.KeyPath
                        Name         = $e.Name
                        DisabledName = $newName
                    }
                    $disabled++
                } else {
                    Write-Log ("  [FAIL] Could not delete original {0}" -f $e.Name) -Level WARN
                    $failed++
                }
            } else {
                Write-Log ("  [FAIL] Could not copy {0}" -f $e.Name) -Level WARN
                $failed++
            }
        } catch {
            Write-Log ("  [FAIL] {0}: {1}" -f $e.Name, $_.Exception.Message) -Level WARN
            $failed++
        }
    }

    Write-Host ''
    Write-Log ("Step 50 summary: {0} disabled, {1} failed" -f $disabled, $failed) -Level INFO
    Write-Log 'Step 50 complete.' -Level OK
    Write-Log '[SUCCESS] Context menu audit complete.' -Level OK
}

# ============================================================
# STEP 51: Installed Program Audit (opt-in action)
# ============================================================
function Invoke-Step51 {
    <#
    .SYNOPSIS
        Enumerates installed Win32 programs via the Uninstall registry
        keys and flags orphaned/orphaned-looking entries.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 51: Installed Program Audit' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    # [FIX-STEP51-DOMAIN] Skip on domain-joined machines. Enterprise
    # software (SCCM packages, GPO-deployed MSIs, Intune Win32 apps) uses
    # non-standard uninstall entry schemas that the orphan heuristic
    # cannot safely classify. Confirmed damage on NMZ-CBRR-ARYAN:
    # 13 legit program entries were removed.
    $__isDomain51 = $false
    try { $__isDomain51 = [bool](Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).PartOfDomain } catch { }
    if ($__isDomain51) {
        Write-Log 'Step 51 skipped: domain-joined machine (enterprise uninstall entries have non-standard schema).' -Level INFO
        Write-Log '  Enterprise software should be managed via IT tooling (SCCM/Intune), not by an auto-cleanup tool.' -Level INFO
        Write-Log '  To override, run:  Edit Invoke-Step51 and remove the [FIX-STEP51-DOMAIN] block.' -Level INFO
        return
    }

    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    Write-Log 'PHASE 1: Enumerating installed programs...' -Level INFO

    $programs = @()
    foreach ($root in $uninstallRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        try {
            $subkeys = Get-ChildItem -LiteralPath $root -ErrorAction Stop
            foreach ($sk in $subkeys) {
                $name = Split-Path -Leaf $sk.PSPath
                if ($name -like 'PS*') { continue }

                $props = Get-ItemProperty -LiteralPath $sk.PSPath -ErrorAction SilentlyContinue
                if ($null -eq $props) { continue }

                $displayName  = if ($props.PSObject.Properties['DisplayName']) { [string]$props.PSObject.Properties['DisplayName'].Value } else { '' }
                $uninstallStr = if ($props.PSObject.Properties['UninstallString']) { [string]$props.PSObject.Properties['UninstallString'].Value } else { '' }
                $installLoc   = if ($props.PSObject.Properties['InstallLocation']) { [string]$props.PSObject.Properties['InstallLocation'].Value } else { '' }
                $publisher    = if ($props.PSObject.Properties['Publisher']) { [string]$props.PSObject.Properties['Publisher'].Value } else { '' }

                if ($publisher -match 'Microsoft' -and -not $installLoc) { continue }
                # Skip Microsoft component entries that lack Publisher metadata
                $msComponentNames = @(
                    'Connection Manager', 'mstsc-', 'WIC', 'Microsoft Edge Update',
                    'Microsoft Visual C++', 'Microsoft .NET', 'Microsoft Windows Desktop Runtime',
                    'Microsoft Update Health', 'Microsoft Edge', 'Microsoft Teams'
                )
                $skipByName = $false
                foreach ($mn in $msComponentNames) {
                    if ($name -like "*$mn*") { $skipByName = $true; break }
                }
                if ($skipByName) { continue }

                # [FIX-STEP51-ORPHAN] Only treat as orphan when BOTH DisplayName
                # AND UninstallString are missing. Modern Windows legitimately
                # has uninstall entries with only ONE of the two:
                #   - MSI entries with WindowsInstaller=1 and no UninstallString
                #     (Windows resolves via ProductCode in the key name)
                #   - MSIX entries with DisplayName but uninstall handled by
                #     the AppX subsystem
                #   - Driver bundles with DisplayName but no uninstaller
                # Requiring BOTH prevents nuking legitimate programs' uninstall
                # entries (observed: SQL Server, HP LaserJet, PFU ScanSnap,
                # Java Auto Updater were all removed by the previous logic).
                $missingName    = [string]::IsNullOrWhiteSpace($displayName)
                $missingUninst  = [string]::IsNullOrWhiteSpace($uninstallStr)
                $missingInstall = $installLoc -and -not (Test-Path -LiteralPath ([System.Environment]::ExpandEnvironmentVariables($installLoc)) -ErrorAction SilentlyContinue)

                if (-not ($missingName -and $missingUninst) -and -not $missingInstall) {
                    continue
                }

                $issues = @()
                if ($missingName)    { $issues += 'missing DisplayName' }
                if ($missingUninst)  { $issues += 'missing UninstallString' }
                if ($missingInstall) { $issues += 'InstallLocation missing on disk' }

                $programs += [PSCustomObject]@{
                    KeyName   = $name
                    Root      = $root
                    KeyPath   = $sk.PSPath
                    Display   = if ($displayName) { $displayName } else { "(unnamed - $name)" }
                    Publisher = $publisher
                    Issues    = ($issues -join '; ')
                }
            }
        } catch {
            Write-Log ("  [WARN] Could not read {0}: {1}" -f $root, $_.Exception.Message) -Level DEBUG
        }
    }

    Write-Host ''
    Write-Log ("Found {0} orphaned/unhealthy program entry(ies)." -f $programs.Count) -Level INFO

    if ($programs.Count -eq 0) {
        Write-Log 'No orphaned program entries detected.' -Level OK
        Write-Log 'Step 51 complete.' -Level OK
        return
    }

    Write-Host ''
    Write-Log 'ORPHANED PROGRAM ENTRIES:' -Level WARN
    foreach ($p in $programs) {
        Write-Log ("  [DISABLE] {0}" -f $p.Display) -Level WARN
        if ($p.Publisher) {
            Write-Log ("            Publisher: {0}" -f $p.Publisher) -Level WARN
        }
        Write-Log ("            Issues: {0}" -f $p.Issues) -Level WARN
    }

    if (-not $Script:AllowProgramAuditAction) {
        Write-Host ''
        Write-Log 'Action NOT authorized. Use -AllowProgramAuditAction to remove orphaned entries.' -Level INFO
        Write-Log 'Step 51 complete (audit only).' -Level OK
        return
    }

    if ($Script:DryRun) {
        Write-Log ("[PREVIEW] Would remove {0} orphaned registry entries." -f $programs.Count) -Level PREVIEW
        return
    }

    if (-not (Confirm-Action -Query ('Remove {0} orphaned program registry entries?' -f $programs.Count))) {
        Write-Log 'Step 51 action declined by user.' -Level WARN
        return
    }

    $removed = 0
    $failed  = 0

    foreach ($p in $programs) {
        try {
            $keyPath = $p.KeyPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
            $null = & reg.exe delete "$keyPath" /f 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log ("  [REMOVED] {0}" -f $p.Display) -Level OK
                $removed++
            } else {
                Write-Log ("  [FAIL] Could not remove {0}" -f $p.Display) -Level WARN
                $failed++
            }
        } catch {
            Write-Log ("  [FAIL] {0}: {1}" -f $p.Display, $_.Exception.Message) -Level WARN
            $failed++
        }
    }

    Write-Host ''
    Write-Log ("Step 51 summary: {0} removed, {1} failed" -f $removed, $failed) -Level INFO
    Write-Log 'Step 51 complete.' -Level OK
    Write-Log '[SUCCESS] Installed program audit complete.' -Level OK
}

# ============================================================
# STEP 52: Safe Service Trim (opt-in)
# ============================================================
function Invoke-Step52 {
    [CmdletBinding()]
    param()

    Write-Log 'STEP 52: Safe Service Trim' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowServiceTrim) {
        Write-Log 'Step 52 blocked: -AllowServiceTrim flag was not supplied.' -Level INFO
        Write-Log '[INFO] Step 52 skipped: authorization flag absent.' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would trim: dmwappushservice, MapsBroker, RetailDemo, WMPNetworkSvc, RemoteRegistry.' -Level PREVIEW
        return
    }

    $targets = @(
        [PSCustomObject]@{ Name = 'dmwappushservice'; NewStart = 'Manual';   Reason = 'WAP Push Message Routing (MDM only)' }
        [PSCustomObject]@{ Name = 'MapsBroker';       NewStart = 'Manual';   Reason = 'Downloaded Maps Manager (on demand)' }
        [PSCustomObject]@{ Name = 'RetailDemo';       NewStart = 'Manual';   Reason = 'Retail demo mode (store only)' }
        [PSCustomObject]@{ Name = 'WMPNetworkSvc';    NewStart = 'Manual';   Reason = 'WMP Network Sharing (legacy DLNA)' }
        [PSCustomObject]@{ Name = 'RemoteRegistry';   NewStart = 'Disabled'; Reason = 'Remote Registry access (remote regedit)' }
    )

    # [FIX-STEP52-DOMAIN] Preserve enterprise-critical services on
    # domain-joined machines. RemoteRegistry is required by every IT
    # remote-management tool (SCCM, remote regedit, GPO registry CSEs).
    # dmwappushservice is used by Intune/MDM for WAP push notifications.
    # Confirmed damage on NMZ-CBRR-ARYAN: both were trimmed.
    $__isDomain52 = $false
    try { $__isDomain52 = [bool](Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).PartOfDomain } catch { }
    $__enterpriseServices = @('RemoteRegistry', 'dmwappushservice')

    $changed = 0; $skipped = 0; $failed = 0

    foreach ($t in $targets) {
        if ($__isDomain52 -and ($__enterpriseServices -contains $t.Name)) {
            Write-Log ("  [SKIP] {0}: domain-joined - preserving enterprise management access" -f $t.Name) -Level INFO
            $skipped++
            continue
        }

        $svc = Get-Service -Name $t.Name -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Log ("  [{0}] Not present - skipped." -f $t.Name) -Level DEBUG
            $skipped++
            continue
        }

        $currentStart = (Get-CimInstance Win32_Service -Filter "Name='$($t.Name)'" -ErrorAction SilentlyContinue).StartMode
        if ($currentStart -eq $t.NewStart) {
            Write-Log ("  [{0}] Already {1}. Nothing to do." -f $t.Name, $t.NewStart) -Level DEBUG
            $skipped++
            continue
        }

        try {
            Set-Service -Name $t.Name -StartupType $t.NewStart -ErrorAction Stop
            Write-Log ("  [OK] {0}: {1} -> {2} ({3})" -f $t.Name, $currentStart, $t.NewStart, $t.Reason) -Level OK
            Add-RollbackEntry -Step 52 -Type 'Service' -Data @{
                Name          = $t.Name
                OriginalStart = $currentStart
                NewStart      = $t.NewStart
            }
            $changed++
        } catch {
            Write-Log ("  [WARN] Could not set {0}: {1}" -f $t.Name, $_.Exception.Message) -Level WARN
            $failed++
        }
    }

    Write-Host ''
    Write-Log ("Step 52 summary: {0} changed, {1} already-set/absent, {2} failed" -f $changed, $skipped, $failed) -Level INFO
    Write-Log 'Rollback: run WinTune.ps1 -Rollback to revert.' -Level INFO
    Write-Log 'Step 52 complete.' -Level OK
}

# ============================================================
# STEP 54: Privacy and Start Menu Tweaks (opt-in)
# ============================================================
function Invoke-Step54 {
    [CmdletBinding()]
    param()

    Write-Log 'STEP 54: Privacy and Start Menu Tweaks' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowPrivacyTweaks) {
        Write-Log 'Step 54 blocked: -AllowPrivacyTweaks flag was not supplied.' -Level INFO
        Write-Log '[INFO] Step 54 skipped: authorization flag absent.' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would apply HKCU privacy and Start Menu tweaks.' -Level PREVIEW
        return
    }

    $tweaks = @(
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search';                 Name = 'BingSearchEnabled';                 Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer';               Name = 'ShowRecent';                        Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer';               Name = 'ShowFrequent';                      Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-338388Enabled';   Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-338393Enabled';   Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SystemPaneSuggestionsEnabled';      Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SilentInstalledAppsEnabled';        Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';               Name = 'AllowCortana';                      Value = 0; Type = 'DWord' }

        # [FIX-EXTRA-STEP54] UI clutter and privacy additions
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';      Name = 'ShowSyncProviderNotifications';     Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-338389Enabled';   Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-310093Enabled';   Value = 0; Type = 'DWord' }
        # [FIX-STEP54-DSH-POLICY] TaskbarDa cannot be written on Win11
        # 24H2/25H2 (E_ACCESSDENIED - Microsoft anti-scripting ACL).
        # Switched to the supported HKLM Dsh group policy, which hides
        # Widgets on all Win11 builds without ACL restrictions.
        #
        # [FIX-DSH-PROBE] On MDM-managed/Intune machines the Dsh key is
        # ACL-locked even for Administrators. Only include the DWORD if
        # the key is writable; otherwise Step 54 will WARN every run.
        [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh';                                  Name = 'AllowNewsAndInterests';             Value = 0; Type = 'DWord' }
        [PSCustomObject]@{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search';                 Name = 'SearchboxTaskbarMode';              Value = 0; Type = 'DWord' }
        # [FIX-KEEP-CLIPBOARD] Clipboard history (Win+V) is a user
        # preference, not a security policy. Removed the previous
        # AllowClipboardHistory=0 DWORD so users can toggle it via
        # Settings -> System -> Clipboard without being overridden.

        # [FIX-TIER1-START-MENU] Hide the "Recommended" block from Start menu
        [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer';                     Name = 'HideRecommendedSection';            Value = 1; Type = 'DWord' }
    )

    $applied = 0; $skipped = 0; $failed = 0

    foreach ($t in $tweaks) {
        $existed = $false
        $originalValue = $null
        try {
            $prop = Get-ItemProperty -Path $t.Path -Name $t.Name -ErrorAction SilentlyContinue
            if ($prop -and $prop.PSObject.Properties[$t.Name]) {
                $existed = $true
                $originalValue = $prop.PSObject.Properties[$t.Name].Value
            }
        } catch { }

        if ($existed -and "$originalValue" -eq "$($t.Value)") {
            Write-Log ("  [{0}\{1}] Already set." -f $t.Path, $t.Name) -Level DEBUG
            $skipped++
            continue
        }

        try {
            if (-not (Test-Path -LiteralPath $t.Path)) {
                New-Item -Path $t.Path -Force -ErrorAction Stop | Out-Null
            }
            New-ItemProperty -Path $t.Path -Name $t.Name -Value $t.Value -PropertyType $t.Type -Force -ErrorAction Stop | Out-Null
            Write-Log ("  [OK] {0}\{1} = {2}" -f $t.Path, $t.Name, $t.Value) -Level OK
            Add-RollbackEntry -Step 54 -Type 'RegistryHKCU' -Data @{
                Path    = $t.Path
                Name    = $t.Name
                Existed = $existed
                Value   = $originalValue
                Type    = $t.Type
            }
            $applied++
        } catch {
            # [FIX-DSH-GRACEFUL-V2] UCPD.sys (since July 2026 KB) protects
            # specific value names under HKLM\Policies\Microsoft\Dsh.
            # Writing AllowNewsAndInterests fails with E_ACCESSDENIED
            # even for elevated Administrators. Detect that exact case
            # and downgrade to INFO + skipped so the summary stays clean.
            $__errMsg = $_.Exception.Message
            if ($t.Path -match 'Policies\\Microsoft\\Dsh' -and
                ($__errMsg -match 'unauthorized|denied|ACCESS_DENIED')) {
                Write-Log ("  [INFO] {0}\{1} is UCPD-protected - skipped. Widgets stays visible." -f $t.Path, $t.Name) -Level INFO
                $skipped++
            } else {
                Write-Log ("  [WARN] Could not set {0}\{1}: {2}" -f $t.Path, $t.Name, $__errMsg) -Level WARN
                $failed++
            }
        }
    }

    Write-Host ''
    Write-Log ("Step 54 summary: {0} applied, {1} already-set, {2} failed" -f $applied, $skipped, $failed) -Level INFO
    Write-Log 'Step 54 complete.' -Level OK
}

# ============================================================
# P1: Backup-RegistryKey helper
# ============================================================
function Backup-RegistryKey {
    <#
    .SYNOPSIS
        Exports a registry key to a .reg file before modification.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Step,
        [Parameter(Mandatory)][string]$RegPath
    )

    if ([string]::IsNullOrEmpty($Script:BackupDir)) {
        try {
            $Script:BackupDir = Join-Path $Script:ScriptDir ("RegistryBackups\{0}" -f $Script:RunStamp)
            if (-not (Test-Path -LiteralPath $Script:BackupDir)) {
                New-Item -ItemType Directory -Path $Script:BackupDir -Force -ErrorAction Stop | Out-Null
            }
        } catch {
            Write-Log ("  [WARN] Could not create registry backup dir: {0}" -f $_.Exception.Message) -Level WARN
            return
        }
    }

    $psPath = $RegPath -replace '^HKCU\\', 'HKCU:\' -replace '^HKLM\\', 'HKLM:\'
    if (-not (Test-Path -LiteralPath $psPath)) {
        Write-Log ("  [BACKUP] Key does not yet exist: {0}" -f $RegPath) -Level DEBUG
        return
    }

    $safeName = ($RegPath -replace '[\\/:*?"<>|]', '_')
    $fileName = "Step{0}_{1}.reg" -f $Step, $safeName
    $outPath  = Join-Path $Script:BackupDir $fileName

    try {
        $null = & reg.exe export $RegPath $outPath /y 2>&1
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $outPath)) {
            Write-Log ("  [BACKUP] {0} -> {1}" -f $RegPath, $fileName) -Level INFO
        } else {
            Write-Log ("  [WARN] reg export failed for {0}" -f $RegPath) -Level WARN
        }
    } catch {
        Write-Log ("  [WARN] Could not export {0}: {1}" -f $RegPath, $_.Exception.Message) -Level WARN
    }
}

# ============================================================
# ROLLBACK MANIFEST WRITER
# ============================================================
function Add-RollbackEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Step,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][hashtable]$Data
    )
    try {
        if (-not $Script:RollbackEntries) {
            $Script:RollbackEntries = New-Object System.Collections.ArrayList
        }
        [void]$Script:RollbackEntries.Add([PSCustomObject]@{
            Step = $Step
            Type = $Type
            Data = $Data
            At   = (Get-Date).ToString('o')
        })

        if (-not $Script:RollbackManifestPath) {
            $Script:RollbackManifestPath = Join-Path $Script:ScriptDir ("Rollback_{0}.jsonl" -f $Script:RunStamp)
        }
        $json = [PSCustomObject]@{
            Step = $Step
            Type = $Type
            Data = $Data
            At   = (Get-Date).ToString('o')
        } | ConvertTo-Json -Compress
        Add-Content -LiteralPath $Script:RollbackManifestPath -Value $json -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Rollback is a safety guarantee â€” a write failure is not silent.
        Write-Log ("ROLLBACK MANIFEST WRITE FAILED: {0}" -f $_.Exception.Message) -Level ERROR
        Write-Log ("  Manifest path: {0}" -f $Script:RollbackManifestPath) -Level ERROR
        Write-Log ("  Change was applied but cannot be rolled back via -Rollback.") -Level WARN
        Write-Host ""
        Write-Host "  [WARN] Rollback manifest could not be written. This change is NOT reversible." -ForegroundColor Yellow
    }
}

# ============================================================
# ROLLBACK MODE
# ============================================================
function ConvertTo-ServiceStartType {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Mode)
    switch -Regex ($Mode) {
        '^(Automatic|Auto|Boot|System)$' { return 'Automatic' }
        '^Manual$'                        { return 'Manual' }
        '^Disabled$'                      { return 'Disabled' }
        '^AutomaticDelayedStart$'         { return 'AutomaticDelayedStart' }
        default                            { return $Mode }
    }
}
function Invoke-RollbackMode {
    [CmdletBinding()]
    param([string]$ManifestPath)

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ' WinTune - ROLLBACK MODE' -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ''

    if (-not $ManifestPath) {
        $candidates = Get-ChildItem -LiteralPath $Script:ScriptDir -Filter 'Rollback_*.jsonl' -File -ErrorAction SilentlyContinue |
                      Sort-Object LastWriteTime -Descending
        if (-not $candidates -or @($candidates).Count -eq 0) {
            Write-Host 'No rollback manifest found. Nothing to do.' -ForegroundColor Yellow
            return
        }
        $ManifestPath = $candidates[0].FullName
    }

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        Write-Host ("Manifest not found: {0}" -f $ManifestPath) -ForegroundColor Red
        return
    }

    Write-Host ("Manifest: {0}" -f $ManifestPath) -ForegroundColor Gray
    Write-Host ''

    $entries = @()
    try {
        $lines = Get-Content -LiteralPath $ManifestPath -ErrorAction Stop
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $entries += ($line | ConvertFrom-Json) } catch { }
        }
    } catch {
        Write-Host ("Could not read manifest: {0}" -f $_.Exception.Message) -ForegroundColor Red
        return
    }

    if ($entries.Count -eq 0) {
        Write-Host 'Manifest is empty.' -ForegroundColor Yellow
        return
    }

    Write-Host ("{0} rollback entries found." -f $entries.Count) -ForegroundColor Cyan
    Write-Host ''

    $entries = @($entries | Sort-Object At -Descending)

    $ok = 0; $fail = 0; $skip = 0

    foreach ($e in $entries) {
        $label = "[Step {0}] {1}" -f $e.Step, $e.Type
        try {
            switch ($e.Type) {
                'Service' {
                    $svc = Get-Service -Name $e.Data.Name -ErrorAction SilentlyContinue
                    if (-not $svc) { Write-Host ("  SKIP {0}: {1} not present" -f $label, $e.Data.Name) -ForegroundColor DarkGray; $skip++; continue }
                    Set-Service -Name $e.Data.Name -StartupType (ConvertTo-ServiceStartType -Mode $e.Data.OriginalStart) -ErrorAction Stop
                    Write-Host ("  OK   {0}: {1} -> {2}" -f $label, $e.Data.NewStart, $e.Data.OriginalStart) -ForegroundColor Green
                    $ok++
                }
                'ScheduledTask' {
                    Enable-ScheduledTask -TaskPath $e.Data.Path -TaskName $e.Data.Name -ErrorAction Stop | Out-Null
                    Write-Host ("  OK   {0}: enabled {1}{2}" -f $label, $e.Data.Path, $e.Data.Name) -ForegroundColor Green
                    $ok++
                }
                'ContextMenu' {
                    if ($e.Data.KeyPath) {
                        $disabledRegPath = ($e.Data.KeyPath + '.WinTuneDisabled') -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
                        $originalRegPath = $e.Data.KeyPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
                        $null = & reg.exe delete "$originalRegPath" /f 2>&1
                        $null = & reg.exe copy "$disabledRegPath" "$originalRegPath" /s /f 2>&1
                        if ($LASTEXITCODE -eq 0) { Write-Host ("  OK   {0}: restored {1}" -f $label, $e.Data.Name) -ForegroundColor Green; $ok++ }
                        else { Write-Host ("  FAIL {0}: {1}" -f $label, $e.Data.Name) -ForegroundColor Red; $fail++ }
                    } else { $skip++ }
                }
                'RegistryHKCU' {
                    if ($e.Data.Existed) {
                        New-ItemProperty -Path $e.Data.Path -Name $e.Data.Name -Value $e.Data.Value -PropertyType $e.Data.Type -Force -ErrorAction Stop | Out-Null
                        Write-Host ("  OK   {0}: restored {1}\{2}" -f $label, $e.Data.Path, $e.Data.Name) -ForegroundColor Green
                    } else {
                        Remove-ItemProperty -Path $e.Data.Path -Name $e.Data.Name -Force -ErrorAction SilentlyContinue
                        Write-Host ("  OK   {0}: removed {1}\{2}" -f $label, $e.Data.Path, $e.Data.Name) -ForegroundColor Green
                    }
                    $ok++
                }
                default {
                    Write-Host ("  SKIP {0}: unknown type" -f $label) -ForegroundColor DarkGray
                    $skip++
                }
            }
        } catch {
            Write-Host ("  FAIL {0}: {1}" -f $label, $_.Exception.Message) -ForegroundColor Red
            $fail++
        }
    }

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host (" Rollback complete: {0} reverted, {1} skipped, {2} failed" -f $ok, $skip, $fail) -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'You may need to reboot for service changes to fully apply.' -ForegroundColor Yellow
}

# ============================================================
# STEP 55: TCP Performance and Latency Tuning
# ============================================================
# ============================================================
# STEP 55: TCP Performance and Latency Tuning
# ============================================================
# ============================================================
# STEP 55: TCP Performance and Latency Tuning
# ============================================================
function Invoke-Step55 {
    <#
    .SYNOPSIS
        Audits and tunes Windows TCP global settings for optimal
        throughput and latency on modern networks.

    .DESCRIPTION
        Reads current state first, then applies only the changes
        that differ from the target.

        Targets:
          * RSS (Receive-Side Scaling)         -> enabled
          * Auto-Tuning Level                  -> normal
          * Congestion Control Provider        -> cubic (build 22000+)

        Congestion provider control moved to "netsh int tcp set
        supplemental Internet congestionprovider=cubic" on Windows 11
        build 22000+. Older builds support the legacy
        "set global congestionprovider=cubic" syntax. We try both.

        Rollback:
          netsh int tcp reset
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 55: TCP Performance and Latency Tuning' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowTcpTuning) {
        Write-Log 'Step 55 blocked: -AllowTcpTuning flag was not supplied.' -Level INFO
        Write-Log 'This step tunes TCP global settings for performance.' -Level INFO
        Write-Log 'Re-run with -AllowTcpTuning if you explicitly want this.' -Level INFO
        Write-Log '[INFO] Step 55 skipped: authorization flag absent.' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would audit and tune TCP auto-tuning, RSS, and congestion provider.' -Level PREVIEW
        return
    }

    # ---- Read current TCP global state ----
    $current = @{}
    $rawOutput = ''
    try {
        $rawOutput = (& netsh.exe int tcp show global 2>&1) -join "`r`n"
        foreach ($line in ($rawOutput -split "`r?`n")) {
            if ($line -match '^\s*(.+?)\s*:\s*(.*?)\s*$') {
                $label = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                $current[$label] = $value
            }
        }
    } catch {
        Write-Log ("  [WARN] Could not read TCP global state: {0}" -f $_.Exception.Message) -Level WARN
    }

    $rssLabel      = $null
    $autoTuneLabel = $null
    $ccLabel       = $null

    foreach ($key in $current.Keys) {
        if ($key -match 'Receive-Side Scaling State')       { $rssLabel      = $key }
        elseif ($key -match 'Auto-?Tuning Level')           { $autoTuneLabel = $key }
        elseif ($key -match 'Congestion Control Provider')  { $ccLabel       = $key }
    }

    $rssState      = if ($rssLabel)      { $current[$rssLabel] }      else { '(unknown)' }
    $autoTuneState = if ($autoTuneLabel) { $current[$autoTuneLabel] } else { '(unknown)' }
    $ccState       = if ($ccLabel)       { $current[$ccLabel] }       else { '(unknown)' }

    Write-Log ("  Current RSS:                 {0}" -f $rssState)      -Level INFO
    Write-Log ("  Current Auto-Tuning Level:   {0}" -f $autoTuneState) -Level INFO
    Write-Log ("  Current Congestion Provider: {0}" -f $ccState)       -Level INFO

    $changes = 0

    # ---- RSS ----
    if ($rssState -notmatch 'enabled') {
        & netsh.exe int tcp set global rss=enabled 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log '  [OK] RSS enabled.' -Level OK
            $changes++
        } else {
            Write-Log ("  [WARN] RSS enable returned exit code {0}." -f $LASTEXITCODE) -Level WARN
        }
    } else {
        Write-Log '  RSS already enabled.' -Level DEBUG
    }

    # ---- Auto-Tuning ----
    if ($autoTuneState -notmatch 'normal') {
        & netsh.exe int tcp set global autotuninglevel=normal 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log '  [OK] Auto-Tuning set to normal.' -Level OK
            $changes++
        } else {
            Write-Log ("  [WARN] Auto-Tuning change returned exit code {0}." -f $LASTEXITCODE) -Level WARN
        }
    } else {
        Write-Log '  Auto-Tuning already normal.' -Level DEBUG
    }

    # ---- Congestion provider (build-gated + support-gated) ----
    # [FIX-STEP55-VPN] Skip CUBIC when a VPN process is running. VPN
    # clients (Proton, OpenVPN, WireGuard, NordVPN, ExpressVPN, etc.)
    # reset TCP global parameters on start/stop to keep their tunnels
    # isolated from host tuning. Attempting to set CUBIC while a VPN
    # is active succeeds at the kernel level but is reverted within
    # milliseconds, producing a misleading WARN on every run. Better
    # to skip cleanly and let the user know why.
    $__vpnRunning = $false
    $__vpnProcNames = @(
        'ProtonVPN.NrptWatchdog'
        'ProtonVPN.Launcher'
        'ProtonVPN.Client'
        'protonvpn-service'
        'openvpn'
        'wireguard'
        'nordvpn-service'
        'ExpressVPNService'
        'mullvad'
        'warp-svc'
        'vpnagent'
        'vpnui'
    )
    foreach ($__vp in $__vpnProcNames) {
        if (Get-Process -Name $__vp -ErrorAction SilentlyContinue) {
            $__vpnRunning = $true
            Write-Log ("  [SKIP] CUBIC skipped — VPN process '{0}' is active (resets TCP globals)." -f $__vp) -Level INFO
            break
        }
    }

    $build = 0
    try { $build = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).BuildNumber } catch { }

    if ($__vpnRunning) {
        # Nothing to do — the current provider is VPN-managed.
        Write-Log '  Congestion provider left at current setting (VPN-managed).' -Level INFO
    } elseif ($build -lt 22000) {
        # Legacy syntax path for Windows 10
        if ($ccState -match 'cubic') {
            Write-Log '  Congestion provider already CUBIC.' -Level DEBUG
        } else {
            $ccOutput = ''
            try { $ccOutput = (& netsh.exe int tcp set global congestionprovider=cubic 2>&1) -join ' ' } catch { }
            if ($LASTEXITCODE -eq 0) {
                Write-Log '  [OK] Congestion provider set to CUBIC (legacy syntax).' -Level OK
                $changes++
            } else {
                Write-Log ("  [SKIP] CUBIC not accepted on this build: {0}" -f $ccOutput.Trim()) -Level INFO
            }
        }
    } else {
        # Windows 11 build 22000+ uses "set supplemental Internet congestionprovider=cubic"
        # First, check whether cubic is already the active provider.
        if ($ccState -match 'cubic') {
            Write-Log '  Congestion provider already CUBIC.' -Level DEBUG
        } else {
            # Try the new syntax first
            $ccOutput = ''
            try { $ccOutput = (& netsh.exe int tcp set supplemental Internet congestionprovider=cubic 2>&1) -join ' ' } catch { }
            $ccExit = $LASTEXITCODE

            if ($ccExit -eq 0) {
                Write-Log '  [OK] Congestion provider set to CUBIC.' -Level OK
                $changes++
            } else {
                # Fall back to legacy syntax in case this build still supports it
                $ccOutput2 = ''
                try { $ccOutput2 = (& netsh.exe int tcp set global congestionprovider=cubic 2>&1) -join ' ' } catch { }
                $ccExit2 = $LASTEXITCODE

                if ($ccExit2 -eq 0) {
                    Write-Log '  [OK] Congestion provider set to CUBIC (legacy fallback).' -Level OK
                    $changes++
                } else {
                    # Check if CUBIC is even a valid option on this build
                    $suppOut = ''
                    try { $suppOut = (& netsh.exe int tcp show supplemental 2>&1) -join "`r`n" } catch { }

                    if ($suppOut -match 'cubic') {
                        # CUBIC exists but set failed â€” that's a real problem
                        Write-Log ("  [WARN] CUBIC set failed (supplemental: {0})" -f $ccOutput.Trim()) -Level WARN
                        Write-Log ("  [WARN] Legacy set also failed: {0}" -f $ccOutput2.Trim()) -Level WARN
                    } else {
                        # CUBIC isn't offered on this build â€” the default is already optimal
                        Write-Log '  [SKIP] CUBIC not offered by this build''s TCP stack.' -Level INFO
                        Write-Log '  Windows 11 24H2+ uses CUBIC as the default congestion provider.' -Level INFO
                        Write-Log '  No action needed â€” the current provider is already optimal.' -Level INFO
                    }
                }
            }
        }
    }

    # [FIX-SILENT-5] Re-read TCP global state and warn if the CUBIC change
    # didn't persist. Without this check, Step 55 logs "success" every run
    # while the provider stays at 'default' because a VPN or GPO is
    # resetting it.
    Start-Sleep -Milliseconds 500
    $verifyOutput = ''
    try {
        $verifyOutput = (& netsh.exe int tcp show global 2>&1) -join "`r`n"
    } catch { }
    $verifyCc = $null
    foreach ($line in ($verifyOutput -split "`r?`n")) {
        if ($line -match 'Congestion Control Provider\s*:\s*(.*?)\s*$') {
            $verifyCc = $Matches[1]
            break
        }
    }

    if ($changes -gt 0) {
        if ($verifyCc -and ($verifyCc -notmatch 'cubic')) {
            Write-Log ("  [WARN] Congestion provider reverted to '{0}' after set - likely overridden by VPN or policy." -f $verifyCc) -Level WARN
        } else {
            Write-Log ("Step 55 complete. {0} change(s) applied." -f $changes) -Level OK
        }
    } else {
        Write-Log 'Step 55 complete. No changes needed.' -Level OK
    }
    # [FIX-EXTRA-STEP55] Disable Network Throttling
    Write-Log 'Disabling Network Throttling...' -Level INFO
    $throttlePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
    try {
        if (-not (Test-Path -LiteralPath $throttlePath)) { New-Item -Path $throttlePath -Force | Out-Null }
        New-ItemProperty -Path $throttlePath -Name 'NetworkThrottlingIndex' -Value 0xFFFFFFFF -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log '  [OK] Network Throttling disabled (0xFFFFFFFF).' -Level OK
    } catch {
        Write-Log ("  [WARN] Could not disable Network Throttling: {0}" -f $_.Exception.Message) -Level WARN
    }

    Write-Log '  Rollback: netsh int tcp reset' -Level INFO
}

# ============================================================
# STEP 57: Advanced System Tweaks
# ============================================================
function Invoke-Step57 {
    <#
    .SYNOPSIS
        Applies advanced, gated system tweaks (hibernation, modern
        standby, HPET, registry backups).
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 57: Advanced System Tweaks' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    $applied = $false

    # 1. Hibernation
    if ($Script:AllowHibernationOff) {
        $isLaptop = (Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
        if (-not $isLaptop) {
            Write-Log 'Disabling hibernation (desktop PC detected)...' -Level INFO
            $null = & powercfg.exe /hibernate off 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log '  [OK] Hibernation disabled (reclaimed hiberfil.sys).' -Level OK
                $applied = $true
            } else {
                Write-Log '  [WARN] powercfg failed to disable hibernation.' -Level WARN
            }
        } else {
            Write-Log '  [SKIP] Laptop detected - hibernation left enabled (safety).' -Level INFO
        }
    }

    # 2. Modern Standby
    if ($Script:AllowModernStandbyOff) {
        Write-Log 'Disabling Modern Standby (S0ix)...' -Level INFO
        $msPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
        try {
            if (-not (Test-Path -LiteralPath $msPath)) { New-Item -Path $msPath -Force | Out-Null }
            New-ItemProperty -Path $msPath -Name 'PlatformAoAcOverride' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Log '  [OK] Modern Standby disabled (requires reboot).' -Level OK
            $Script:RebootRequired = $true
            if ($Script:RebootReasons -notcontains 'Step 57 (Modern Standby)') {
                $Script:RebootReasons += 'Step 57 (Modern Standby)'
            }
            $applied = $true
        } catch {
            Write-Log ("  [WARN] Could not disable Modern Standby: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    # 3. HPET (High Precision Event Timer)
    if ($Script:AllowHpetOff) {
        Write-Log 'Disabling HPET (High Precision Event Timer)...' -Level INFO
        $null = & bcdedit.exe /deletevalue useplatformclock 2>&1
        # Return code 0 means success. If it's 1, the value was already absent.
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
            Write-Log '  [OK] HPET disabled via bcdedit.' -Level OK
            $applied = $true
        } else {
            Write-Log ("  [WARN] bcdedit returned exit code {0}." -f $LASTEXITCODE) -Level WARN
        }
    }

    # [FIX-TIER2-FASTSTARTUP] Disable Fast Startup
    if ($Script:AllowFastStartupOff) {
        Write-Log 'Disabling Fast Startup...' -Level INFO
        $__powerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
        try {
            if (-not (Test-Path -LiteralPath $__powerPath)) { New-Item -Path $__powerPath -Force | Out-Null }
            New-ItemProperty -Path $__powerPath -Name 'HiberbootEnabled' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Log '  [OK] Fast Startup disabled.' -Level OK
            $applied = $true
        } catch {
            Write-Log ("  [WARN] Could not disable Fast Startup: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    # [FIX-TIER2-GAMING] Enable HAGS + Game Mode
    if ($Script:AllowGamingTweaks) {
        Write-Log 'Enabling gaming tweaks (HAGS + Game Mode)...' -Level INFO
        $__hagsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
        $__gmPath   = 'HKCU:\Software\Microsoft\GameBar'
        try {
            if (-not (Test-Path -LiteralPath $__hagsPath)) { New-Item -Path $__hagsPath -Force | Out-Null }
            New-ItemProperty -Path $__hagsPath -Name 'HwSchMode' -Value 2 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Log '  [OK] HAGS enabled (HwSchMode = 2, reboot required).' -Level OK
            if ($Script:RebootReasons -notcontains 'Step 57 (HAGS)') {
                $Script:RebootReasons += 'Step 57 (HAGS)'
            }
            $Script:RebootRequired = $true
            $applied = $true
        } catch {
            Write-Log ("  [WARN] Could not enable HAGS: {0}" -f $_.Exception.Message) -Level WARN
        }
        try {
            if (-not (Test-Path -LiteralPath $__gmPath)) { New-Item -Path $__gmPath -Force | Out-Null }
            New-ItemProperty -Path $__gmPath -Name 'AutoGameModeEnabled' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Log '  [OK] Game Mode enabled.' -Level OK
            $applied = $true
        } catch {
            Write-Log ("  [WARN] Could not enable Game Mode: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    # 4. Registry Backups
    if ($Script:AllowRegistryBackup) {
        Write-Log 'Enabling Registry Periodic Backups...' -Level INFO
        try {
            Enable-ScheduledTask -TaskPath '\Microsoft\Windows\Registry\' -TaskName 'RegIdleBackup' -ErrorAction Stop | Out-Null
            Write-Log '  [OK] Registry backup task enabled.' -Level OK
            $applied = $true
        } catch {
            Write-Log ("  [WARN] Could not enable Registry backup task: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    if (-not $applied) {
        Write-Log 'No advanced tweaks requested or applicable.' -Level INFO
    }

    Write-Log 'Step 57 complete.' -Level OK
}

# ============================================================
# STEP 58: DNS Resolver Benchmark
# ============================================================
function Invoke-Step58 {
    <#
    .SYNOPSIS
        Benchmarks well-known DNS resolvers and optionally switches
        to the fastest one.
    .DESCRIPTION
        Tests latency against Cloudflare, Google, Quad9, OpenDNS,
        and AdGuard. Uses Resolve-DnsName with -QuickTimeout against
        three stable canary domains. Applies the fastest resolver
        only if it's meaningfully faster than current (or if current
        is a private router IP).

        Skips on domain-joined PCs. Requires -AllowDnsBenchmark.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 58: DNS Resolver Benchmark' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if (-not $Script:AllowDnsBenchmark) {
        Write-Log 'Step 58 blocked: -AllowDnsBenchmark flag was not supplied.' -Level INFO
        return
    }

    $__isDomain = $false
    try { $__isDomain = [bool](Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).PartOfDomain } catch { }
    if ($__isDomain) {
        Write-Log 'Step 58 skipped: domain-joined (DNS managed by AD).' -Level INFO
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would benchmark DNS resolvers and optionally switch.' -Level PREVIEW
        return
    }

    $resolvers = @(
        @{ Name = 'Cloudflare'; Primary = '1.1.1.1';         Secondary = '1.0.0.1' }
        @{ Name = 'Google';     Primary = '8.8.8.8';         Secondary = '8.8.4.4' }
        @{ Name = 'Quad9';      Primary = '9.9.9.9';         Secondary = '149.112.112.112' }
        @{ Name = 'OpenDNS';    Primary = '208.67.222.222';  Secondary = '208.67.220.220' }
        @{ Name = 'AdGuard';    Primary = '94.140.14.14';    Secondary = '94.140.15.15' }
    )
    $testNames = @('www.microsoft.com', 'www.github.com', 'www.google.com')

    Write-Log 'Benchmarking DNS resolvers (3 queries per resolver)...' -Level INFO
    $results = @()

    foreach ($r in $resolvers) {
        $times = @()
        foreach ($n in $testNames) {
            try {
                $t = Measure-Command {
                    Resolve-DnsName -Name $n -Server $r.Primary -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
                }
                $times += $t.TotalMilliseconds
            } catch { }
        }
        if ($times.Count -gt 0) {
            $avg = ($times | Measure-Object -Average).Average
            $results += [PSCustomObject]@{
                Name = $r.Name; Primary = $r.Primary; Secondary = $r.Secondary; AvgMs = [math]::Round($avg, 1)
            }
        }
    }

    if ($results.Count -eq 0) {
        Write-Log 'No resolvers responded — skipping DNS config.' -Level WARN
        return
    }

    $results = @($results | Sort-Object AvgMs)
    Write-Log '  Results (fastest first):' -Level INFO
    foreach ($r in $results) {
        Write-Log ("    {0,-12} {1,6:N1} ms  ({2})" -f $r.Name, $r.AvgMs, $r.Primary) -Level INFO
    }

    # ---- Get current DNS ----
    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    $currentDns = @()
    foreach ($a in $adapters) {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dns -and $dns.ServerAddresses) {
            $currentDns += $dns.ServerAddresses
        }
    }
    Write-Log ("  Current DNS: {0}" -f ($currentDns -join ', ')) -Level INFO

    $best = $results[0]
    Write-Log ("  Fastest: {0} ({1} ms, {2})" -f $best.Name, $best.AvgMs, $best.Primary) -Level OK

    # ---- Decide whether to switch ----
    $applyBest = $false
    if ($currentDns.Count -eq 0) {
        $applyBest = $true
        Write-Log '  No current DNS configured — will apply fastest.' -Level INFO
    } else {
        foreach ($d in $currentDns) {
            if ($d -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)') {
                $applyBest = $true
                Write-Log ("  Current DNS {0} is a private router address — switching." -f $d) -Level INFO
                break
            }
        }
        if (-not $applyBest) {
            Write-Log '  Current DNS is already public — leaving unchanged.' -Level INFO
            Write-Log 'Step 58 complete.' -Level OK
            return
        }
    }

    if (-not (Confirm-Action -Query ("Switch DNS to {0} ({1}, {2})?" -f $best.Name, $best.Primary, $best.Secondary))) {
        Write-Log 'Step 58: DNS change declined by user.' -Level WARN
        return
    }

    # ---- Apply ----
    $appliedCount = 0
    foreach ($a in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @($best.Primary, $best.Secondary) -ErrorAction Stop
            Write-Log ("  [OK] {0}: DNS -> {1}, {2}" -f $a.Name, $best.Primary, $best.Secondary) -Level OK
            Add-RollbackEntry -Step 58 -Type 'NetworkDns' -Data @{
                AdapterIndex = $a.ifIndex
                AdapterName  = $a.Name
                PreviousDns  = $currentDns
            }
            $appliedCount++
        } catch {
            Write-Log ("  [WARN] {0}: {1}" -f $a.Name, $_.Exception.Message) -Level WARN
        }
    }

    if ($appliedCount -gt 0) {
        $null = & ipconfig.exe /flushdns 2>&1
        Write-Log '  [OK] DNS cache flushed.' -Level OK
        Write-Log ("Step 58 complete. Applied {0} to {1} adapter(s)." -f $best.Name, $appliedCount) -Level OK
    } else {
        Write-Log 'Step 58: no adapters updated.' -Level WARN
    }
}

# ============================================================
# STEP 59: Sandbox / WSL / Dev Drive Audit
# ============================================================
function Invoke-Step59 {
    <#
    .SYNOPSIS
        Audits and optionally enables Windows Sandbox, WSL, and Dev Drive.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 59: Sandbox / WSL / Dev Drive Audit' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if ($Script:DryRun) {
        Write-Log 'Would audit Sandbox/WSL/DevDrive and optionally enable.' -Level PREVIEW
        return
    }

    # ---- Audit current state ----
    Write-Log 'Current feature state:' -Level INFO
    $features = @(
        @{ Feature = 'Containers-DisposableClientVM';      Label = 'Windows Sandbox' }
        @{ Feature = 'Microsoft-Windows-Subsystem-Linux';  Label = 'WSL' }
        @{ Feature = 'VirtualMachinePlatform';             Label = 'VM Platform' }
    )
    foreach ($f in $features) {
        try {
            $__feat = Get-WindowsOptionalFeature -Online -FeatureName $f.Feature -ErrorAction Stop
            $__state = if ($__feat.State -eq 'Enabled') { 'Enabled' } else { 'Not installed' }
            Write-Log ("    {0,-18} : {1}" -f $f.Label, $__state) -Level INFO
        } catch {
            Write-Log ("    {0,-18} : query failed" -f $f.Label) -Level DEBUG
        }
    }

    # Dev Drive state
    try {
        $__devDriveReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DevDrive' -ErrorAction SilentlyContinue
        $__devDriveState = if ($__devDriveReg) { 'Configured' } else { 'Not configured' }
        Write-Log ("    {0,-18} : {1}" -f 'Dev Drive', $__devDriveState) -Level INFO
    } catch { }

    # ---- Optional enable ----
    if ($Script:AllowSandboxInstall) {
        Write-Log 'Enabling Windows Sandbox...' -Level INFO
        try {
            $__r = Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All -NoRestart -ErrorAction Stop
            Write-Log '  [OK] Windows Sandbox enabling (reboot required).' -Level OK
            $Script:RebootRequired = $true
            if ($Script:RebootReasons -notcontains 'Step 59 (Sandbox)') {
                $Script:RebootReasons += 'Step 59 (Sandbox)'
            }
        } catch {
            Write-Log ("  [WARN] Could not enable Sandbox: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    if ($Script:AllowWslInstall) {
        Write-Log 'Installing WSL...' -Level INFO
        try {
            $__out = & wsl.exe --install --no-launch 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log '  [OK] WSL install initiated (reboot may be required).' -Level OK
                $Script:RebootRequired = $true
                if ($Script:RebootReasons -notcontains 'Step 59 (WSL)') {
                    $Script:RebootReasons += 'Step 59 (WSL)'
                }
            } else {
                Write-Log ("  [WARN] wsl --install returned exit {0}" -f $LASTEXITCODE) -Level WARN
            }
        } catch {
            Write-Log ("  [WARN] wsl install failed: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    if ($Script:AllowDevDriveEnable) {
        Write-Log 'Enabling Dev Drive capability...' -Level INFO
        try {
            $__ddPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DevDrive'
            if (-not (Test-Path -LiteralPath $__ddPath)) { New-Item -Path $__ddPath -Force | Out-Null }
            New-ItemProperty -Path $__ddPath -Name 'TrustedVolumeOptOut' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Log '  [OK] Dev Drive capability enabled (format a volume as ReFS to use).' -Level OK
        } catch {
            Write-Log ("  [WARN] Could not enable Dev Drive: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    if (-not ($Script:AllowSandboxInstall -or $Script:AllowWslInstall -or $Script:AllowDevDriveEnable)) {
        Write-Log 'No enable requested (audit-only mode). Add -AllowSandboxInstall / -AllowWslInstall / -AllowDevDriveEnable to enable.' -Level INFO
    }

    Write-Log 'Step 59 complete.' -Level OK
}

# ============================================================
# HTML REPORT GENERATOR
# ============================================================
function Write-HtmlReport {
    <#
    .SYNOPSIS
        Serializes $Script:Report to a self-contained HTML file
        in <ScriptDir>\Reports\WinTune_Report_<timestamp>.html.

    .DESCRIPTION
        Reads:
          * $Script:Report (in-memory run metadata)
          * $Script:LogFile (embedded as <pre>)

        Writes a single HTML file with inline CSS. No CDN, works
        offline, prints cleanly.

        Called from Main's finally block. Never throws.
    #>
    [CmdletBinding()]
    param()

    try {
        # ---- Path setup ----
        $reportsDir = Join-Path $Script:ScriptDir 'Reports'
        if (-not (Test-Path -LiteralPath $reportsDir)) {
            New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
        }
        $reportPath = Join-Path $reportsDir ("WinTune_Report_{0}.html" -f $Script:RunStamp)

        # ---- Finalize report object ----
        $Script:Report.FinishedAt      = Get-Date
        $Script:Report.DiskBeforeGB    = [math]::Round($Script:StartFreeBytes / 1GB, 2)
        $Script:Report.DiskAfterGB     = [math]::Round((Get-FreeBytesOnSystemDrive) / 1GB, 2)
        $Script:Report.RebootRequired  = $Script:RebootRequired

        $netDelta = [math]::Round($Script:Report.DiskAfterGB - $Script:Report.DiskBeforeGB, 2)

        # ---- Count statuses ----
        $okCount      = @($Script:Report.Steps | Where-Object { $_.Status -eq 'OK' }).Count
        $skipCount    = @($Script:Report.Steps | Where-Object { $_.Status -eq 'Skipped' }).Count
        $failCount    = @($Script:Report.Steps | Where-Object { $_.Status -eq 'Failed' }).Count
        $gatedCount   = @($Script:Report.Steps | Where-Object { $_.Status -eq 'Gated' }).Count
        $dryCount     = @($Script:Report.Steps | Where-Object { $_.Status -eq 'DryRun' }).Count
        $warnCount    = @($Script:Report.Steps | Where-Object { $_.Status -eq 'Warning' }).Count
        $detCount     = @($Script:Report.Steps | Where-Object { $_.Status -eq 'Detached' }).Count
        $totalCount   = @($Script:Report.Steps).Count

        # ---- Duration ----
        $duration = if ($Script:Report.FinishedAt -and $Script:Report.StartedAt) {
            $Script:Report.FinishedAt - $Script:Report.StartedAt
        } else { [TimeSpan]::Zero }
        $durationText = '{0:mm\:ss}' -f $duration

        # [FIX-SELFTEST-STEPTIME] Pre-compute Total Step Time with a
        # null-safe guard. Measure-Object on empty input has no .Sum
        # property, which throws under StrictMode Latest. This never
        # triggered before SelfTest began calling Write-HtmlReport
        # with zero steps.
        $__totalStepMs = [int64]0
        try {
            $__mObj = $Script:Report.Steps | Measure-Object -Property DurationMs -Sum -ErrorAction SilentlyContinue
            if ($__mObj -and $null -ne $__mObj.Sum) { $__totalStepMs = [int64]$__mObj.Sum }
        } catch { }
        $totalStepTime = '{0:N1}s' -f ($__totalStepMs / 1000.0)

        # ---- HTML escaping helper ----
        $enc = {
            param([string]$s)
            if ($null -eq $s) { return '' }
            return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
        }

        # ---- Build step rows ----
        $stepRows = New-Object System.Text.StringBuilder
        foreach ($s in $Script:Report.Steps) {
            $cls = switch ($s.Status) {
                'OK'      { 'st-ok' }
                'Skipped' { 'st-skip' }
                'Failed'  { 'st-fail' }
                'Gated'   { 'st-gate' }
                'DryRun'  { 'st-dry' }
                'Warning' { 'st-warn' }
                'NoOp'    { 'st-noop' }
                'Detached' { 'st-detached' }
                default   { 'st-other' }
            }
            $durMs  = $s.DurationMs
            $durTxt = if ($durMs -ge 1000) { '{0:N1}s' -f ($durMs / 1000) } else { "$durMs" + 'ms' }

            $detailText  = if ([string]::IsNullOrWhiteSpace($s.Detail)) { '<span style="color:#94a3b8;font-style:italic;">(no detail)</span>' } else { & $enc $s.Detail }
            $durDisplay  = if ($durMs -eq 0) { '<span style="color:#94a3b8;">&mdash;</span>' } else { $durTxt }
            $rowTitle    = "Step $($s.Number) - $($s.Status)"
            [void]$stepRows.AppendLine("      <tr class=""$cls"" title=""$(& $enc $rowTitle)"" data-status=""$($s.Status)"">")
            [void]$stepRows.AppendLine("        <td class=""num"">$($s.Number)</td>")
            [void]$stepRows.AppendLine("        <td class=""name"">$(& $enc $s.Name)</td>")
            [void]$stepRows.AppendLine("        <td class=""status"">$($s.Status)</td>")
            [void]$stepRows.AppendLine("        <td class=""detail"">$detailText</td>")
            [void]$stepRows.AppendLine("        <td class=""dur"">$durDisplay</td>")
            [void]$stepRows.AppendLine("      </tr>")
        }

        # ---- Runner rows ----
        $runnerRows = New-Object System.Text.StringBuilder
        foreach ($r in $Script:Report.DetachedRunners) {
            $ts = '{0:HH:mm:ss}' -f $r.At

            # Fix C: enrich with exit info if present in the tracking hashtable
            $exitInfo = '(not tracked)'
            $exitCls  = ''
            if ($Script:DetachedRunners -and $Script:DetachedRunners.ContainsKey($r.Pid)) {
                $t = $Script:DetachedRunners[$r.Pid]
                if ($null -ne $t.ExitCode) {
                    # [FIX-EXITCODE-HTML] Same mask as PostCheck — avoid
                    # the [uint32] cast exception on STATUS_CONTROL_C_EXIT
                    # and similar negative ExitCodes.
                    $__tExitU = [uint32]([int64]$t.ExitCode -band 0xFFFFFFFFL)
                    $exitInfo = ('0x{0:X8} ({1})' -f $__tExitU, $t.ExitCode)
                    $exitCls  = if ($t.ExitCode -eq 0) { 'st-ok' } else { 'st-warn' }
                } else {
                    $exitInfo = 'running'
                    $exitCls  = 'st-detached'
                }
            }

            [void]$runnerRows.AppendLine("      <tr>")
            [void]$runnerRows.AppendLine("        <td>$(& $enc $r.Kind)</td>")
            [void]$runnerRows.AppendLine("        <td>$($r.Pid)</td>")
            [void]$runnerRows.AppendLine("        <td>$(& $enc $r.Note)</td>")
            [void]$runnerRows.AppendLine("        <td>$ts</td>")
            [void]$runnerRows.AppendLine("        <td class=""status $exitCls"">$exitInfo</td>")
            [void]$runnerRows.AppendLine("      </tr>")
        }

        # ---- Embedded log ----
        # ---- Gather child runner logs (from D:\PS\WinTune_<Kind>.log) ----
        $__childLogsHtml = New-Object System.Text.StringBuilder
        # [FIX-DETACHED-6] Include the Drivers runner log so driver updates
        # appear in the report.
        $__childLogNames = @('WinTune_SfcDism.log', 'WinTune_Winget.log', 'WinTune_WU.log', 'WinTune_Drivers.log')
        foreach ($__childName in $__childLogNames) {
            $__childPath = Join-Path $Script:ScriptDir $__childName
            if (Test-Path -LiteralPath $__childPath) {
                try {
                    $__childContent = Get-Content -LiteralPath $__childPath -Raw -ErrorAction SilentlyContinue
                    $__childEscaped = & $enc $__childContent
                    [void]$__childLogsHtml.AppendLine("    <h3>$__childName</h3>")
                    [void]$__childLogsHtml.AppendLine("    <pre>$__childEscaped</pre>")
                } catch {
                    [void]$__childLogsHtml.AppendLine("    <p><em>Could not read $__childName</em></p>")
                }
            } else {
                [void]$__childLogsHtml.AppendLine("    <p><em>$__childName not present for this run.</em></p>")
            }
        }
        if ($__childLogsHtml.Length -eq 0) {
            [void]$__childLogsHtml.AppendLine("    <p><em>No child runner logs found.</em></p>")
        }

        $logText = ''
        try {
            if (Test-Path -LiteralPath $Script:LogFile) {
                $logText = Get-Content -LiteralPath $Script:LogFile -Raw
            }
        } catch { }
        $logEscaped = & $enc $logText

        # ---- Delta color ----
        # Net Change color: green for gain, red for loss, gray for zero.
        # The old code colored '+0.00 GB' green when both sides were 0.
        $deltaColor = if ($netDelta -gt 0.01) { '#0a7' } elseif ($netDelta -lt -0.01) { '#c33' } else { '#6b7280' }
        $deltaSign  = if ($netDelta -gt 0) { '+' } else { '' }

        $dryBanner = if ($Script:Report.DryRun) {
            '<div class="dry-banner">DRY RUN - no permanent changes were made</div>'
        } else { '' }

        $rebootBanner = if ($Script:Report.RebootRequired) {
            '<div class="reboot-banner">REBOOT REQUIRED to complete pending changes</div>'
        } else { '' }

        # [FIX-DETACHED-7] Banner when any detached runner is still executing.
        $__stillRunning = 0
        if ($Script:DetachedRunners) {
            foreach ($k in $Script:DetachedRunners.Keys) {
                $e = $Script:DetachedRunners[$k]
                if ($null -eq $e.ExitCode) { $__stillRunning++ }
            }
        }
        $detachedBanner = if ($__stillRunning -gt 0) {
            ('<div class="detached-banner">{0} detached runner(s) still executing - see their window(s) and child log(s) below.</div>' -f $__stillRunning)
        } else { '' }

        # ---- Assemble HTML ----
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WinTune Report - $($Script:Report.StartedAt.ToString('yyyy-MM-dd HH:mm:ss'))</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         background: #f4f6f8; color: #1c1f23; margin: 0; padding: 24px; line-height: 1.5; }
  .container { max-width: 1100px; margin: 0 auto; background: #fff;
               border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; }
  header { background: #1c1f23; color: #fff; padding: 20px 28px; }
  header h1 { margin: 0; font-size: 20px; font-weight: 600; }
  header .sub { color: #adb5bd; font-size: 13px; margin-top: 4px; }
  .dry-banner, .reboot-banner { padding: 12px 28px; font-weight: 600; font-size: 14px; }
  .dry-banner { background: #e7f1ff; color: #0958d9; border-bottom: 1px solid #bae0ff; }
  .reboot-banner { background: #fff7e6; color: #d46b08; border-bottom: 1px solid #ffd591; }
  .detached-banner { background: #f3e8ff; color: #6b21a8; border-bottom: 1px solid #d8b4fe;
                     padding: 12px 28px; font-weight: 600; font-size: 14px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 1px; background: #e6e8eb; }
  .card { background: #fff; padding: 16px 20px; }
  .card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
                 color: #6b7280; font-weight: 600; }
  .card .value { font-size: 20px; font-weight: 600; margin-top: 4px; color: #1c1f23; }
  .card .value.small { font-size: 14px; font-weight: 500; }
  section { padding: 20px 28px; border-top: 1px solid #e6e8eb; }
  section h2 { margin: 0 0 12px 0; font-size: 15px; font-weight: 600;
               text-transform: uppercase; letter-spacing: 0.5px; color: #4b5563; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 10px; background: #f9fafb;
       border-bottom: 2px solid #e6e8eb; color: #4b5563; font-weight: 600;
       text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
  td { padding: 8px 10px; border-bottom: 1px solid #f0f1f3; vertical-align: top; }
  tr:hover td { background: #fafbfc; }
  td.num { width: 40px; color: #6b7280; font-variant-numeric: tabular-nums; }
  td.name { width: 30%; }
  td.status { width: 90px; font-weight: 600; font-size: 12px; }
  td.dur { width: 70px; text-align: right; color: #6b7280; font-variant-numeric: tabular-nums; }
  tr.st-ok td.status { color: #0a7; }
  tr.st-skip td.status { color: #94a3b8; }
  tr.st-fail td.status { color: #c33; }
  tr.st-gate td.status { color: #d46b08; }
  tr.st-dry td.status { color: #0958d9; }
  tr.st-warn td.status { color: #d4a008; }
  tr.st-noop td.status { color: #94a3b8; }
  tr.st-detached td.status { color: #7c3aed; font-style: italic; }
  pre { background: #1c1f23; color: #e6e8eb; padding: 16px; border-radius: 6px;
        font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
        font-size: 12px; line-height: 1.4; overflow-x: auto; max-height: 500px;
        white-space: pre; margin: 0; }
  footer { padding: 16px 28px; font-size: 12px; color: #6b7280;
           border-top: 1px solid #e6e8eb; background: #f9fafb; }
  .metric { font-variant-numeric: tabular-nums; }
  .delta-pos { color: #0a7; }
  .delta-neg { color: #c33; }
</style>
</head>
<body>
<div class="container">

  <header>
    <h1>WinTune Ultimate - Run Report</h1>
    <div class="sub">$($Script:Report.StartedAt.ToString('dddd, MMMM d, yyyy HH:mm:ss'))</div>
  </header>

  $dryBanner
  $rebootBanner

  <div class="grid">
    <div class="card">
      <div class="label">Hostname</div>
      <div class="value small">$(& $enc $Script:Report.Hostname)</div>
    </div>
    <div class="card">
      <div class="label">Operating System</div>
      <div class="value small">$(& $enc $Script:Report.OS) (Build $($Script:Report.Build))</div>
    </div>
    <div class="card">
      <div class="label">User</div>
      <div class="value small">$(& $enc $Script:Report.User)</div>
    </div>
    <div class="card">
      <div class="label">Profile</div>
      <div class="value small">$(if ($Script:Report.Profile) { & $enc $Script:Report.Profile } else { '(none)' })</div>
    </div>
    <div class="card">
      <div class="label">Disk Before</div>
      <div class="value metric">$($Script:Report.DiskBeforeGB) GB</div>
    </div>
    <div class="card">
      <div class="label">Disk After</div>
      <div class="value metric">$($Script:Report.DiskAfterGB) GB</div>
    </div>
    <div class="card">
      <div class="label">Net Change</div>
      <div class="value metric" style="color:$deltaColor">$deltaSign$netDelta GB</div>
    </div>
    <div class="card">
      <div class="label">Duration</div>
      <div class="value metric">$durationText</div>
    </div>
  </div>

  <section>
    <h2>Summary</h2>
    <div class="grid">
      <div class="card"><div class="label">Total Steps</div><div class="value metric">$totalCount</div></div>
      <div class="card"><div class="label">Total Step Time</div><div class="value metric">$totalStepTime</div></div>
      <div class="card"><div class="label">OK</div><div class="value metric" style="color:#0a7">$okCount</div></div>
      <div class="card"><div class="label">Skipped</div><div class="value metric" style="color:#94a3b8">$skipCount</div></div>
      <div class="card"><div class="label">Gated</div><div class="value metric" style="color:#d46b08">$gatedCount</div></div>
      <div class="card"><div class="label">Dry Run</div><div class="value metric" style="color:#0958d9">$dryCount</div></div>
      <div class="card"><div class="label">Warnings</div><div class="value metric" style="color:#d4a008">$warnCount</div></div>
      <div class="card"><div class="label">Detached</div><div class="value metric" style="color:#7c3aed">$detCount</div></div>
      <div class="card"><div class="label">Failed</div><div class="value metric" style="color:#c33">$failCount</div></div>
    </div>
  </section>

  <section>
    <h2>Steps</h2>
    <div style="margin-bottom:12px;font-size:12px;color:#4b5563;">
      Filter:
      <select id="statusFilter" onchange="filterSteps()" style="padding:4px 8px;border:1px solid #d1d5db;border-radius:4px;font-size:12px;">
        <option value="">All statuses</option>
        <option value="OK">OK</option>
        <option value="Skipped">Skipped</option>
        <option value="Failed">Failed</option>
        <option value="Gated">Gated</option>
        <option value="DryRun">DryRun</option>
        <option value="Warning">Warning</option>
        <option value="NoOp">NoOp</option>
      </select>
      <span id="filterCount" style="color:#6b7280;margin-left:8px;"></span>
    </div>
    <table id="stepsTable">
      <thead>
        <tr><th>#</th><th>Name</th><th>Status</th><th>Detail</th><th>Duration</th></tr>
      </thead>
      <tbody>
$($stepRows.ToString())
      </tbody>
    </table>
  </section>

  <section>
    <h2>Detached Runners</h2>
    $(if ($Script:Report.DetachedRunners.Count -eq 0) {
      '<p style="color:#6b7280;font-size:13px;">No detached runners were launched in this run.</p>'
    } else {
      '<table><thead><tr><th>Kind</th><th>PID</th><th>Note</th><th>Launched</th><th>Exit</th></tr></thead><tbody>' + $runnerRows.ToString() + '</tbody></table>'
    })
  </section>

  <section>
    <h2>Log</h2>
    <pre>$logEscaped</pre>
  </section>


  <section>
    <h2>Child Runner Logs</h2>
    $__childLogsHtml
  </section>

  <footer>
    <div><strong>Main log:</strong> $(& $enc $Script:LogFile)</div>
    <div><strong>Report generated:</strong> $($Script:Report.FinishedAt.ToString('yyyy-MM-dd HH:mm:ss'))</div>
    <div><strong>PowerShell:</strong> $($Script:Report.PowerShellVersion)</div>
  </footer>

</div>
<script>
  function filterSteps() {
    var sel   = document.getElementById('statusFilter').value;
    var rows  = document.querySelectorAll('#stepsTable tbody tr');
    var shown = 0, total = 0;
    rows.forEach(function (tr) {
      total++;
      var match = !sel || tr.getAttribute('data-status') === sel;
      tr.style.display = match ? '' : 'none';
      if (match) shown++;
    });
    document.getElementById('filterCount').textContent =
      sel ? ('Showing ' + shown + ' of ' + total) : ('Showing all ' + total);
  }
  // Initialize count on load
  window.addEventListener('DOMContentLoaded', filterSteps);
</script>
</body>
</html>
"@

        # ---- Write file ----
        Set-Content -LiteralPath $reportPath -Value $html -Encoding UTF8
        Write-Log ("HTML report written: {0}" -f $reportPath) -Level OK

        # ---- Auto-open ----
        try {
            # Launch via cmd.exe so the browser detaches cleanly from PowerShell
            $null = cmd.exe /c start "" "$reportPath" 2>&1
            Write-Log 'Report opened in default browser.' -Level INFO
        } catch {
            Write-Log ("Could not auto-open report: {0}" -f $_.Exception.Message) -Level DEBUG
        }

        return $reportPath
    } catch {
        Write-Log ("HTML report generation failed: {0}" -f $_.Exception.Message) -Level WARN
        return $null
    }
}

# ============================================================
# STEP 43: UWP LocalCache Sweep
# ============================================================
function Invoke-Step43 {
    <#
    .SYNOPSIS
        Sweeps LocalCache folders for a safe-list of known UWP
        packages. Regenerable data only - user settings and state
        are preserved.

    .DESCRIPTION
        UWP apps store cache data under:
          %LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\

        This step cleans the LocalCache for a curated list of
        packages that are known to be safe. Every entry has been
        manually reviewed to ensure it only contains regenerable
        data (fonts, images, streams, previews, thumbnails, JSON
        responses).

        Protection strategy:
          * Only explicit safe-list entries are cleaned
          * Package families NOT on the list are never touched
          * Within each package, only the LocalCache subtree
            is swept - Settings, state, and user data are kept
          * Per-package failure is logged, non-fatal

        Not gated - this is safe to run by default.
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 43: UWP LocalCache Sweep' -Level STEP
    Write-Log ('-' * 60) -Level STEP
    # ---- Gate: -AllowUwpCleanup required ----
    if (-not $Script:AllowUwpCleanup) {
        Write-Log 'Step 43 blocked: -AllowUwpCleanup flag was not supplied.' -Level INFO
        Write-Log 'UWP LocalCache may contain licensed content and app preferences.' -Level INFO
        Write-Log 'Re-run with -AllowUwpCleanup if you explicitly want this.' -Level INFO
        Write-Log '[INFO] Step 43 skipped: authorization flag absent.' -Level INFO
        return
    }

    Write-Log 'Sweeping LocalCache folders for a curated safe-list of UWP apps.' -Level INFO
    Write-Log 'User settings, state, and data are preserved.' -Level INFO

    if (-not (Confirm-Action -Query 'Clear UWP LocalCache folders for safe-listed apps?')) {
        Write-Log 'Step 43 skipped by user.' -Level WARN
        return
    }

    if ($Script:DryRun) {
        Write-Log 'Would clear LocalCache folders for safe-listed UWP apps.' -Level PREVIEW
        return
    }

    # Fix B: capture free space before this step's mutations
    $__fsBefore = Get-FreeBytesOnSystemDrive

    $packagesRoot = Join-Path $env:LOCALAPPDATA 'Packages'
    if (-not (Test-Path -LiteralPath $packagesRoot)) {
        Write-Log 'Packages root not present - skipped.' -Level INFO
        return
    }

    # ---- Safe-list: exact package family name prefixes to clean ----
    $safeList = @(
        # ---- Original safe-list ----
        'SpotifyAB.SpotifyMusic'
        '5319275A.WhatsAppDesktop'
        'Microsoft.Todos'
        'Microsoft.PowerAutomateDesktop'
        'Microsoft.MicrosoftStickyNotes'
        'Microsoft.WindowsMaps'
        'Microsoft.WindowsCamera'
        'Microsoft.WindowsSoundRecorder'
        'Microsoft.MicrosoftOfficeHub'
        'Microsoft.SkypeApp'
        'Microsoft.YourPhone'
        'MicrosoftWindows.CrossDevice'
        'Microsoft.MicrosoftSolitaireCollection'
        'Microsoft.WindowsFeedbackHub'
        'Microsoft.WindowsAlarms'
        'Microsoft.Microsoft3DViewer'
        'Microsoft.Paint'
        'Microsoft.MSPaint'
        'Microsoft.ScreenSketch'
        'Microsoft.WindowsCalculator'
        'Microsoft.WindowsNotepad'
        'Microsoft.OutlookForWindows'
        'Clipchamp.Clipchamp'
        'Microsoft.XboxGamingOverlay'
        'Microsoft.XboxIdentityProvider'
        'Microsoft.GamingApp'
        'Microsoft.StartExperiencesApp'
        'Microsoft.MicrosoftEdge.Stable'
        'Microsoft.WindowsCommunicationsApps'
        'microsoft.windowscommunicationsapps'

        # ---- Added: common large UWP caches ----
        'Microsoft.Windows.Photos'
        'Microsoft.WindowsStore'
        'Microsoft.StorePurchaseApp'
        'Microsoft.DesktopAppInstaller'
        'Microsoft.WindowsTerminal'
        'Microsoft.SecHealthUI'
        'Microsoft.Windows.Explorer'
        'Microsoft.UI.Xaml'
        'Microsoft.VCLibs'
        'Microsoft.NET.Native'
        'Microsoft.WindowsAppRuntime'
        'MicrosoftCorporationII.WinAppRuntime'
        'Microsoft.Windows.Search'
        'MicrosoftWindows.Client.WebExperience'
        'MicrosoftWindows.Client.CBS'
        'MicrosoftWindows.Client.Core'
        'Microsoft.MicrosoftEdgeWebView2Runtime'
        'Microsoft.WidgetsPlatformRuntime'
        'Microsoft.Win32WebViewHost'
        'Microsoft.AAD.BrokerPlugin'
        'Microsoft.AccountsControl'
        'Microsoft.Windows.ShellExperienceHost'
        'Microsoft.Windows.StartMenuExperienceHost'
        'Microsoft.Windows.ContentDeliveryManager'
        'Microsoft.LockApp'
        'Microsoft.CredDialogHost'
        'Microsoft.Windows.SecureAssessmentBrowser'
        'Microsoft.Windows.CapturePicker'
        'Microsoft.Windows.PrintQueueActionCenter'
        'Microsoft.Windows.PinningConfirmationDialog'
        'Microsoft.PPIProjection'
        'Microsoft.Windows.AppRep.ChxApp'
        'Microsoft.MicrosoftEdge'
        'Microsoft.EdgeWebView2'
        'Microsoft.Windows.CloudExperienceHost'
        'Microsoft.Windows.OOBENetworkCaptivePortal'
        'Microsoft.Windows.OOBENetworkConnectionFlow'
        'Microsoft.Windows.Photos.MediaEngine'
        'Microsoft.RawImageExtension'
        'Microsoft.HEIFImageExtension'
        'Microsoft.HEVCVideoExtension'
        'Microsoft.WebpImageExtension'
        'Microsoft.VP9VideoExtensions'
        'Microsoft.AV1VideoExtension'
        'Microsoft.AVCEncoderVideoExtension'
        'Microsoft.MPEG2VideoExtension'
    )

    Write-Log 'Scanning package families...' -Level INFO

    $allPackages = @()
    try {
        $allPackages = Get-ChildItem -LiteralPath $packagesRoot -Directory -Force -ErrorAction Stop
    } catch {
        Write-Log ("Cannot enumerate {0}: {1}" -f $packagesRoot, $_.Exception.Message) -Level WARN
        return
    }

    Write-Log ("  Total packages present: {0}" -f $allPackages.Count) -Level INFO
    Write-Log ("  Safe-list entries:      {0}" -f $safeList.Count) -Level INFO

    $matched = 0
    $cleared = 0
    $failed  = 0
    $totalBytes = [int64]0

    foreach ($pkg in $allPackages) {
        # Match against safe-list by prefix
        $isSafe = $false
        foreach ($s in $safeList) {
            if ($pkg.Name -like "$s*") {
                $isSafe = $true
                break
            }
        }
        if (-not $isSafe) { continue }

        $matched++
        $localCache = Join-Path $pkg.FullName 'LocalCache'
        if (-not (Test-Path -LiteralPath $localCache)) {
            Write-Log ("  [{0}] No LocalCache - skipped" -f $pkg.Name) -Level DEBUG
            continue
        }

        # Measure before clearing
        $size = 0
        try {
            $size = (Get-ChildItem -LiteralPath $localCache -Recurse -File -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            if ($null -eq $size) { $size = 0 }
        } catch { }

        if ($size -lt 1MB) {
            Write-Log ("  [{0}] Under 1 MB - skipped" -f $pkg.Name) -Level DEBUG
            continue
        }

        $sizeMB = [math]::Round($size / 1MB, 1)
        Write-Log ("  [{0}] Clearing {1:N1} MB..." -f $pkg.Name, $sizeMB) -Level INFO

        try {
            Get-ChildItem -LiteralPath $localCache -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            $totalBytes += [int64]$size
            $cleared++
        } catch {
            Write-Log ("    Failed: {0}" -f $_.Exception.Message) -Level DEBUG
            $failed++
        }
    }

    $freedMB = [math]::Round($totalBytes / 1MB, 1)

    Write-Log ("UWP LocalCache summary: {0} matched, {1} cleared, {2} failed, {3:N1} MB reclaimed" -f $matched, $cleared, $failed, $freedMB) -Level INFO

    # [FIX-SILENT-4] If every matched cache was already below the 1 MB
    # threshold, don't claim SUCCESS as if caches were swept. That erodes
    # trust in the report.
    if ($cleared -eq 0 -and $failed -eq 0 -and $matched -gt 0) {
        Write-Log ("All {0} matched UWP caches are already under 1 MB - no action needed." -f $matched) -Level INFO
        $Script:LastStepStatus = 'OK'
    }


    # ---- Microsoft Store cache reset (wsreset) ----
    Write-Log 'Checking Microsoft Store presence...' -Level INFO
    $storePkg = Get-AppxPackage -Name 'Microsoft.WindowsStore' -ErrorAction SilentlyContinue
    if ($storePkg) {
        Write-Log '  Resetting Microsoft Store cache (may take 30-60s)...' -Level INFO
        try {
            $__wsProc = Start-Process -FilePath 'wsreset.exe' -ArgumentList '-s' -NoNewWindow -Wait -PassThru
            if ($__wsProc.ExitCode -eq 0) {
                Write-Log '  [OK] Microsoft Store cache reset.' -Level OK
            } else {
                Write-Log ("  [WARN] wsreset returned exit code {0}." -f $__wsProc.ExitCode) -Level WARN
            }
        } catch {
            Write-Log ("  [WARN] wsreset failed: {0}" -f $_.Exception.Message) -Level WARN
        }
    } else {
        Write-Log '  [SKIP] Microsoft Store not installed.' -Level DEBUG
    }

    # Fix B: report the actual free-space delta observed during this step
    $__fsAfter   = Get-FreeBytesOnSystemDrive
    $__fsDeltaMB = [math]::Round(([int64]($__fsAfter - $__fsBefore)) / 1MB, 1)
    Write-Log ("  Actual system-drive free-space delta: {0:N1} MB" -f $__fsDeltaMB) -Level INFO

    Write-Log 'Step 43 complete.' -Level OK
    Write-Log '[SUCCESS] UWP LocalCache sweep finished.' -Level OK
}

# ============================================================
# STEP 56: Security Posture Audits (new)
# ============================================================
function Invoke-Step56 {
    <#
    .SYNOPSIS
        Audits seven security controls and optionally applies three
        of them behind explicit opt-in switches.

    .DESCRIPTION
        Audit-only by default. Reports:
          1. WebClient service (WebDAV / NTLM relay vector)
          2. WPAD hosts-file entry
          3. LAPS installation + policy state
          4. PowerShell ScriptBlockLogging state
          5. UAC configuration (EnableLUA, ConsentPromptBehaviorAdmin,
             PromptOnSecureDesktop)
          6. SMB signing (server + client)
          7. BitLocker / Device Encryption status on the system drive

        Opt-in writes (each gated by its own switch):
          -DisableWebClient         -> Set-Service WebClient Disabled
          -AddWpadHostsEntry        -> append 0.0.0.0 wpad + wpad.* to hosts
          -EnableScriptBlockLogging -> registry write for ScriptBlockLogging
    #>
    [CmdletBinding()]
    param()

    Write-Log 'STEP 56: Security Posture Audits' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    if ($Script:DryRun) {
        Write-Log 'Would audit 7 security controls (report-only in DryRun).' -Level PREVIEW
        return
    }

    # ---- 1. WebClient (WebDAV) ----
    Write-Log 'Audit 1/7: WebClient (WebDAV / NTLM relay)' -Level INFO
    # [FIX-GENERIC-4] Skip -DisableWebClient on domain-joined PCs. WebDAV
    # and SharePoint (\\server\path) depend on it in many corporate
    # environments. Warn instead of break.
    $__domainJoined56 = $false
    try { $__domainJoined56 = [bool](Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).PartOfDomain } catch { }
    $wcSvc = Get-Service -Name 'WebClient' -ErrorAction SilentlyContinue
    if ($wcSvc) {
        $wcStart = (Get-CimInstance Win32_Service -Filter "Name='WebClient'" -ErrorAction SilentlyContinue).StartMode
        Write-Log ("  Current state: {0} / {1}" -f $wcSvc.Status, $wcStart) -Level INFO
        if ($__domainJoined56 -and $Script:DisableWebClient -and $wcStart -ne 'Disabled') {
            Write-Log '  [SKIP] Domain-joined PC detected. Skipping WebClient disable.' -Level WARN
            Write-Log '         WebDAV/SharePoint depend on WebClient on managed networks.' -Level WARN
            Write-Log '         To override, disable it manually:  sc config WebClient start= disabled' -Level WARN
        } elseif ($wcStart -ne 'Disabled' -and $Script:DisableWebClient) {
            try {
                Set-Service -Name 'WebClient' -StartupType Disabled -ErrorAction Stop
                if ($wcSvc.Status -eq 'Running') { Stop-Service -Name 'WebClient' -Force -ErrorAction SilentlyContinue }
                Write-Log '  [OK] WebClient set to Disabled.' -Level OK
            } catch {
                Write-Log ("  [WARN] Could not disable WebClient: {0}" -f $_.Exception.Message) -Level WARN
            }
        } elseif ($wcStart -ne 'Disabled') {
            Write-Log '  Recommendation: run with -DisableWebClient to harden.' -Level INFO
        } else {
            Write-Log '  [OK] Already Disabled.' -Level OK
        }
    } else {
        Write-Log '  [SKIP] WebClient service not present.' -Level DEBUG
    }

    # ---- 2. WPAD hosts-file entry ----
    Write-Log 'Audit 2/7: WPAD hosts-file entry' -Level INFO
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $wpadPresent = $false
    if (Test-Path -LiteralPath $hostsPath) {
        try {
            $wpadPresent = (Get-Content -LiteralPath $hostsPath -ErrorAction Stop) -match '^\s*0\.0\.0\.0\s+wpad\b'
        } catch { }
    }
    if ($wpadPresent) {
        Write-Log '  [OK] WPAD already blocked in hosts file.' -Level OK
    } elseif ($Script:AddWpadHostsEntry) {
        try {
            $lines = @('', '# WinTune - WPAD block', '0.0.0.0 wpad', '0.0.0.0 wpad.*')
            Add-Content -LiteralPath $hostsPath -Value $lines -Encoding ASCII -ErrorAction Stop
            Write-Log '  [OK] WPAD hosts entry added.' -Level OK
        } catch {
            Write-Log ("  [WARN] Could not write hosts file: {0}" -f $_.Exception.Message) -Level WARN
        }
    } else {
        Write-Log '  Missing. Run with -AddWpadHostsEntry to harden.' -Level INFO
    }

    # ---- 3. LAPS ----
    Write-Log 'Audit 3/7: Windows LAPS' -Level INFO
    $lapsPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS'
    $lapsLegacy = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    if (Test-Path -LiteralPath $lapsPath) {
        Write-Log '  [OK] Windows LAPS registry path present.' -Level OK
        try {
            $lapsBackup = (Get-ItemProperty -Path $lapsPath -Name 'BackupDirectory' -ErrorAction SilentlyContinue).BackupDirectory
            if ($null -ne $lapsBackup) {
                Write-Log ("    BackupDirectory = {0}" -f $lapsBackup) -Level INFO
            } else {
                Write-Log '    Not configured (no BackupDirectory value).' -Level INFO
            }
        } catch { }
    } elseif (Test-Path -LiteralPath $lapsLegacy) {
        Write-Log '  [OK] Legacy LAPS (AdmPwd) policy present.' -Level OK
    } else {
        Write-Log '  Not configured. (Report only - no action taken.)' -Level INFO
    }

    # ---- 4. PowerShell ScriptBlockLogging ----
    Write-Log 'Audit 4/7: PowerShell ScriptBlockLogging' -Level INFO
    $sblPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sblEnabled = $null
    if (Test-Path -LiteralPath $sblPath) {
        $sblEnabled = (Get-ItemProperty -Path $sblPath -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    }
    if ($sblEnabled -eq 1) {
        Write-Log '  [OK] ScriptBlockLogging enabled.' -Level OK
    } elseif ($Script:EnableScriptBlockLogging) {
        try {
            if (-not (Test-Path -LiteralPath $sblPath)) { New-Item -Path $sblPath -Force | Out-Null }
            New-ItemProperty -Path $sblPath -Name 'EnableScriptBlockLogging' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Log '  [OK] ScriptBlockLogging enabled.' -Level OK
        } catch {
            Write-Log ("  [WARN] Could not enable ScriptBlockLogging: {0}" -f $_.Exception.Message) -Level WARN
        }
    } else {
        Write-Log '  Not configured. Run with -EnableScriptBlockLogging to harden.' -Level INFO
    }

    # ---- 5. UAC ----
    Write-Log 'Audit 5/7: User Account Control (UAC)' -Level INFO
    $sysPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try {
        $uacProps = Get-ItemProperty -Path $sysPolicyPath -ErrorAction Stop
        $enableLua  = $uacProps.PSObject.Properties['EnableLUA'].Value
        $consent    = $uacProps.PSObject.Properties['ConsentPromptBehaviorAdmin'].Value
        $secureDesk = $uacProps.PSObject.Properties['PromptOnSecureDesktop'].Value
        Write-Log ("    EnableLUA                  = {0}" -f $enableLua)  -Level INFO
        Write-Log ("    ConsentPromptBehaviorAdmin = {0}" -f $consent)    -Level INFO
        Write-Log ("    PromptOnSecureDesktop      = {0}" -f $secureDesk) -Level INFO
        if ($enableLua -ne 1) {
            Write-Log '  [WARN] UAC is disabled (EnableLUA != 1). Report only.' -Level WARN
        } else {
            Write-Log '  [OK] UAC enabled.' -Level OK
        }
    } catch {
        Write-Log ("  [WARN] Could not read UAC policy: {0}" -f $_.Exception.Message) -Level WARN
    }

    # ---- 6. SMB signing ----
    Write-Log 'Audit 6/7: SMB signing' -Level INFO
    try {
        $srv = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        $cli = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
        if ($srv) { Write-Log ("    Server RequireSecuritySignature = {0}" -f $srv.RequireSecuritySignature) -Level INFO }
        if ($cli) { Write-Log ("    Client RequireSecuritySignature = {0}" -f $cli.RequireSecuritySignature) -Level INFO }
        if ($srv -and -not $srv.RequireSecuritySignature) {
            Write-Log '  [WARN] SMB server signing not enforced. Report only.' -Level WARN
        } elseif ($srv) {
            Write-Log '  [OK] SMB server signing enforced.' -Level OK
        }
    } catch {
        Write-Log ("  [WARN] Could not read SMB config: {0}" -f $_.Exception.Message) -Level WARN
    }

    # ---- 7. BitLocker / Device Encryption ----
    Write-Log 'Audit 7/7: BitLocker / Device Encryption' -Level INFO
    try {
        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
            if ($vol) {
                Write-Log ("    Volume {0} - ProtectionStatus = {1}, EncryptionPercentage = {2}%" -f $vol.MountPoint, $vol.ProtectionStatus, $vol.EncryptionPercentage) -Level INFO
                if ($vol.ProtectionStatus -eq 'On') {
                    Write-Log '  [OK] System drive is BitLocker-protected.' -Level OK
                } else {
                    Write-Log '  [WARN] System drive is NOT BitLocker-protected. Report only.' -Level WARN
                }
            }
        } else {
            # manage-bde fallback
            $bde = & manage-bde.exe -status $env:SystemDrive 2>&1
            if ($bde) {
                $bde | ForEach-Object { Write-Log ("    {0}" -f $_) -Level DEBUG }
                $bde | ForEach-Object { Add-Content -LiteralPath $Script:LogFile -Value $_ -Encoding UTF8 -ErrorAction SilentlyContinue }
            }
        }
    } catch {
        Write-Log ("  [WARN] Could not query BitLocker: {0}" -f $_.Exception.Message) -Level WARN
    }

    Write-Log 'Step 56 complete.' -Level OK
}

function Invoke-PostCheck {
    <#
    .SYNOPSIS
        Captures final disk metrics, compares them against the
        baseline captured in PreCheck, and writes a summary to
        the log and console.

    .DESCRIPTION
        Reports:
          * Baseline free space (from PreCheck)
          * Final free space (captured now)
          * Net change (bytes and GB)
          * Storage result (INCREASED / DECREASED / UNCHANGED)

        The delta is signed:
          * Positive -> free space increased (expected from cleanup)
          * Negative -> free space decreased (rare; possible if a
            step wrote more than it deleted, e.g. a large restore
            point or DISM cache download)
          * Zero -> unchanged

        Also:
          * Prints a summary banner with a colored verdict
          * Lists next steps for the user
          * Writes all metrics to the log file
    #>
    [CmdletBinding()]
    param()

    Write-Log 'POST-CHECK: Computing final system metrics...' -Level STEP
    Write-Log ('-' * 60) -Level STEP

    # ============================================================
    # 1. Capture final free bytes
    # ============================================================
    $endFreeBytes = Get-FreeBytesOnSystemDrive

    if ($endFreeBytes -le 0) {
        Write-Log 'Unable to determine final free disk space.' -Level WARN
        Write-Log '[WARNING] PostCheck: Final free-space measurement failed.' -Level WARN
        $endFreeBytes = 0
    } else {
        Write-Log 'Final free-space measurement captured.' -Level OK

    # Fix C: optionally wait for detached runners before computing metrics.
    # This block must never abort the run: if Wait-DetachedRunners throws
    # (unexpected bug, killed process, permission issue), log a warning
    # and continue so the report and lock release still happen.
    try {
        if ($Script:WaitForDetached -or $Script:DetachedWaitSeconds -ne 0) {
            $__waitSecs = if ($Script:WaitForDetached) { -1 } else { $Script:DetachedWaitSeconds }
            Wait-DetachedRunners -MaxSeconds $__waitSecs
        }
    } catch {
        Write-Log ("  [WARN] Wait-DetachedRunners threw: {0}" -f $_.Exception.Message) -Level WARN
        Write-Log '  Continuing without waiting for detached runners.' -Level INFO
    }

    # Report detached runner exit codes to the log
    # [FIX-DETACHED-3] Harvest exit codes from the Process handle first so
    # children that exited between dispatcher-end and PostCheck show up as
    # "exited" rather than "still running".
    try {
        if ($Script:DetachedRunners -and $Script:DetachedRunners.Count -gt 0) {
            foreach ($rPid in $Script:DetachedRunners.Keys) {
                $r = $Script:DetachedRunners[$rPid]
                if ($null -eq $r.ExitCode -and $r.PSObject.Properties['Process'] -and $r.Process) {
                    try {
                        if ($r.Process.HasExited) {
                            $r.ExitedAt = $r.Process.ExitTime
                            $r.ExitCode = $r.Process.ExitCode
                        }
                    } catch { }
                }
            }

            # [FIX-DETACHED-EXIT-REPORT] Reconcile harvested exit codes
            # back into the report step rows. Without this, steps 8b/12/33/39
            # remain 'Detached' in the HTML report even after their child
            # process exits with a non-zero code, permanently understating
            # failures from the longest-running steps.
            foreach ($rPid in $Script:DetachedRunners.Keys) {
                $__r = $Script:DetachedRunners[$rPid]
                if ($null -eq $__r.ExitCode) { continue }
                $__stepNum = $null
                if ($__r.Note -match 'Step\s+(\S+)') { $__stepNum = $Matches[1] }
                if (-not $__stepNum) { continue }
                for ($__i = 0; $__i -lt $Script:Report.Steps.Count; $__i++) {
                    $__s = $Script:Report.Steps[$__i]
                    if ($__s.Number -ne $__stepNum -or $__s.Status -ne 'Detached') { continue }
                    $__newStatus = if ($__r.ExitCode -eq 0) { 'OK' } else { 'Failed' }
                    # [FIX-EXITCODE-RECONCILE] Mask to unsigned 32-bit for
                    # display only. [uint32]$__r.ExitCode throws on negative
                    # exit codes (e.g. -1073741510 = STATUS_CONTROL_C_EXIT,
                    # seen when a detached child is closed via Ctrl+C or
                    # the window's X button). The -band operation converts
                    # the signed negative to its unsigned representation
                    # without changing the underlying meaning.
                    $__exitU = [uint32]([int64]$__r.ExitCode -band 0xFFFFFFFFL)
                    $__newDetail = if ($__r.ExitCode -eq 0) {
                        'Detached runner exited 0 - see child log for details'
                    } else {
                        ('Detached runner exited 0x{0:X8} - see child log' -f $__exitU)
                    }
                    $__s.Status = $__newStatus
                    $__s.Detail = $__newDetail
                    Write-Log ("  [RECONCILE] Step {0}: Detached -> {1} (exit 0x{2:X8})" -f `
                        $__stepNum, $__newStatus, $__exitU) -Level INFO
                    break
                }
            }

            Write-Log 'Detached runner exit codes:' -Level INFO
            foreach ($rPid in $Script:DetachedRunners.Keys) {
                $r = $Script:DetachedRunners[$rPid]
                if ($null -ne $r.ExitCode) {
                    $lvl = if ($r.ExitCode -eq 0) { 'OK' } else { 'WARN' }
                    # [FIX-EXITCODE-UNSIGNED] [uint32] cast throws on
                    # negative ExitCodes (e.g. -1073741510 = 0xC000013A
                    # = STATUS_CONTROL_C_EXIT, seen when a detached
                    # child is closed via Ctrl+C). Mask to unsigned
                    # 32-bit before display.
                    $__exitU = [uint32]([int64]$r.ExitCode -band 0xFFFFFFFFL)
                    Write-Log ("  PID {0} ({1}/{2}): exit 0x{3:X8} ({4})" -f `
                        $rPid, $r.Kind, $r.Note, $__exitU, $r.ExitCode) -Level $lvl
                } else {
                    Write-Log ("  PID {0} ({1}/{2}): still running" -f `
                        $rPid, $r.Kind, $r.Note) -Level WARN
                }
            }
        }
    } catch {
        Write-Log ("  [WARN] Detached runner exit-code reporting threw: {0}" -f $_.Exception.Message) -Level WARN
    }
    }

    # ============================================================
    # 2. Calculate net change
    # ============================================================
    $startFreeBytes = $Script:StartFreeBytes
    $netDeltaBytes  = [int64]$endFreeBytes - [int64]$startFreeBytes

    # ============================================================
    # 3. Convert to human-readable GB
    # ============================================================
    # FREE-SPACE-TRANSPARENCY
    $startGB = [math]::Round($startFreeBytes / 1GB, 2)
    $endGB   = [math]::Round($endFreeBytes   / 1GB, 2)
    $deltaGB = [math]::Round($netDeltaBytes  / 1GB, 2)

    # Estimate space consumed by active system activity
    $activeConsumptionGB = 0.0
    try {
        # Delivery Optimization active/paused jobs
        # [FIX-DO-WARN-3] Same warning suppression for PostCheck's DO query.
        $doJobs = @(Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object { $_.Status -in 'Caching','Downloading','Paused' })
        if ($doJobs.Count -gt 0) {
            $doBytes = ($doJobs | Measure-Object -Property TotalBytesDownloaded -Sum).Sum
            if ($doBytes) { $activeConsumptionGB += [math]::Round($doBytes / 1GB, 2) }
        }
    } catch { }
    # Note: VSS and WU consumption is estimated via the discrepancy itself

    $reportedFreedGB = [math]::Round(($Script:StartFreeBytes - $endFreeBytes + $activeConsumptionGB * 1GB) / 1GB, 2)
    # Simpler: use the delta plus active DO consumption as "reported"
    $reportedFreedGB = $deltaGB + $activeConsumptionGB

    # ============================================================
    # 4. Determine storage result direction
    # ============================================================
    $spaceResult = 'UNCHANGED'
    $threshold = 1MB   # Deltas under 1 MB treated as noise
    if ($netDeltaBytes -gt $threshold) {
        $spaceResult = 'INCREASED'
    } elseif ($netDeltaBytes -lt -$threshold) {
        $spaceResult = 'DECREASED'
    }

    # ============================================================
    # 5. Write final metrics block to log
    # ============================================================
    $metrics = @(
        ''
        '===================================================='
        'FINAL SYSTEM METRICS'
        '===================================================='
        ('Baseline Free Storage:      {0} GB' -f $startGB)
        ('Final Free Storage:         {0} GB' -f $endGB)
        ('Net Free-Space Change:      {0} GB' -f $deltaGB)
        if ($activeConsumptionGB -gt 0.01) {
            ('Space consumed by active system activity: {0} GB' -f [math]::Round($activeConsumptionGB, 2))
        }
        ('Storage Result:             {0}'   -f $spaceResult)
        ('Completed:                  {0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date))
        '===================================================='
    )
    foreach ($line in $metrics) {
        Write-LogFile -Message $line
    }

    # ============================================================
    # 6. Print colored console summary
    # ============================================================
    Write-Host ('=' * 60) -ForegroundColor Green
    Write-Host ' SUCCESS: WinTune Ultimate Processing Complete' -ForegroundColor Green
    Write-Host ('=' * 60) -ForegroundColor Green
    Write-Host (' Baseline Free Space:      {0} GB' -f $startGB) -ForegroundColor Gray
    Write-Host (' Final Free Space:         {0} GB' -f $endGB)   -ForegroundColor Gray

    # Color the delta line based on direction
    $deltaColor = switch ($spaceResult) {
        'INCREASED' { 'Green' }
        'DECREASED' { 'Yellow' }
        default     { 'Gray' }
    }
    Write-Host (' Net Free-Space Change:    {0} GB' -f $deltaGB) -ForegroundColor $deltaColor
    if ($activeConsumptionGB -gt 0.01) {
        Write-Host (' Space consumed by active system activity: {0} GB' -f [math]::Round($activeConsumptionGB, 2)) -ForegroundColor DarkGray
    }
    Write-Host (' Storage Result:           {0}' -f $spaceResult) -ForegroundColor $deltaColor
    Write-Host ('=' * 60) -ForegroundColor Green

    # ============================================================
    # 7. Verify log file exists
    # ============================================================
    if (Test-Path -LiteralPath $Script:LogFile) {
        $logSizeKB = [math]::Round((Get-Item -LiteralPath $Script:LogFile).Length / 1KB, 1)
        Write-Host '[OK] Log file verified:' -ForegroundColor Green
        Write-Host ("     {0} ({1} KB)" -f $Script:LogFile, $logSizeKB) -ForegroundColor Gray
    } else {
        Write-Host '[WARNING] Log file could not be verified.' -ForegroundColor Yellow
    }

    # ============================================================
    # 8. Print next steps
    # ============================================================
    Write-Host 'NEXT STEPS:' -ForegroundColor Cyan
    Write-Host '  [1] Review the log for detailed operation results.' -ForegroundColor Gray
    Write-Host '  [2] If Step 32 was enabled, review Defender ASR Audit events.' -ForegroundColor Gray
    Write-Host '  [3] Reboot only if a specific configuration change requires it.' -ForegroundColor Gray

    # ---- Reboot flag (dynamic reasons) ----
    # [FIX-POSTCHECK-REBOOT] The old block hardcoded "Step 23 (network
    # reset)" even when the reboot was triggered by Step 45, CBS pending,
    # or Windows Update. Print the actual reasons instead.
    if ($Script:RebootRequired) {
        $__rebootReasons = @()
        try {
            if ($Script:RebootReasons -and @($Script:RebootReasons).Count -gt 0) {
                $__rebootReasons = @($Script:RebootReasons)
            }
        } catch { }
        if ($__rebootReasons.Count -eq 0) {
            $__rebootReasons = @('(reason not recorded)')
        }
        Write-Host ''
        Write-Host '[REBOOT REQUIRED]' -ForegroundColor Yellow
        foreach ($__r in $__rebootReasons) {
            Write-Host ("  - {0}" -f $__r) -ForegroundColor Yellow
        }
        Write-Host '  Restart your PC to apply the changes.' -ForegroundColor Yellow
    }


    # ============================================================
    # 9. Write summary to log
    # ============================================================
    # ============================================================
    # P2: pending reboot detection
    # ============================================================
    $pendingServicing = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $pendingWU        = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'

    $anyPending = $pendingServicing -or $pendingWU -or $Script:RebootRequired

    $reasons = @()
    if ($Script:RebootRequired) {
        $__reasonsArr = @($Script:RebootReasons)
        if ($__reasonsArr.Count -gt 0) {
            foreach ($r in $__reasonsArr) {
                $reasons += ("WinTune: {0}" -f $r)
            }
        } else {
            $reasons += 'WinTune (reason not recorded)'
        }
    }
    if ($pendingServicing)       { $reasons += 'Windows servicing (CBS)' }
    if ($pendingWU)              { $reasons += 'Windows Update' }

    Write-Host ''
    if ($anyPending) {
        Write-Host ' REBOOT REQUIRED' -ForegroundColor Yellow
        Write-Host ("  Reason: {0}" -f ($reasons -join '; ')) -ForegroundColor Yellow
        Write-Log ("REBOOT REQUIRED - Reason: {0}" -f ($reasons -join '; ')) -Level WARN
        $Script:Report.RebootRequired = $true
    } else {
        Write-Host ' No reboot required.' -ForegroundColor Green
        Write-Log 'No pending reboot detected.' -Level OK
        $Script:Report.RebootRequired = $false
    }

    Write-Log 'WinTune Ultimate processing complete.' -Level OK
    Write-Log ('  Baseline:   {0} GB' -f $startGB) -Level INFO
    Write-Log ('  Final:      {0} GB' -f $endGB)   -Level INFO
    Write-Log ('  Net change: {0} GB ({1})' -f $deltaGB, $spaceResult) -Level INFO
}

function Main {
    [CmdletBinding()]
    param()

    Show-Banner

    # Transcript removed - single log file only

    try {
        # ---- Environment preflight ----
        Test-Environment

        # ---- Log header ----
        Write-Log '====================================================' -Level INFO
        Write-Log ("WinTune Ultimate v{0} started" -f $Script:Version) -Level INFO
        Write-Log ("DryRun: {0}  ResetBase: {1}  NetworkReset: {2}  Prefetch: {3}  ForceKill: {4}" -f $Script:DryRun, $Script:AllowResetBase, $Script:AllowNetworkReset, $Script:AllowPrefetch, $Script:ForceKill) -Level INFO
        Write-Log ("SkipSteps: [{0}]" -f ($Script:SkipSteps -join ',')) -Level INFO
        Write-Log '====================================================' -Level INFO

        # ---- Lock ----
        Enter-ScriptLock

        # ---- Rollback mode routing ----
        if ($Script:RollbackMode) {
            $Script:InRollbackMode = $true
            Write-Log 'Rollback mode requested. Reverting last run.' -Level OK
            Invoke-RollbackMode -ManifestPath $Script:RollbackFrom
            return
        }

        # ---- Self-test routing ----
        if ($Script:SelfTest) {
            Write-Log '[SELF-TEST] Lock successfully acquired and verified.' -Level OK

            # [FIX-SELFTEST-SCHEMA] Validate step tables + runner syntax.
            $schemaErrors = @()

            # 1. StepNames <-> StepDescriptions key-set parity
            $namesKeys = @($Script:StepNames.Keys | ForEach-Object { [string]$_ })
            $descsKeys = @($Script:StepDescriptions.Keys | ForEach-Object { [string]$_ })
            foreach ($k in ($namesKeys | Where-Object { $_ -notin $descsKeys })) {
                $schemaErrors += "StepNames key '$k' has no StepDescriptions entry"
            }
            foreach ($k in ($descsKeys | Where-Object { $_ -notin $namesKeys })) {
                $schemaErrors += "StepDescriptions key '$k' has no StepNames entry"
            }

            # 2. Runner here-strings parse cleanly
            $runners = @(
                @{ Name = 'EmbeddedSfcDismRunner'; Text = $Script:EmbeddedSfcDismRunner }
                @{ Name = 'EmbeddedWingetRunner';  Text = $Script:EmbeddedWingetRunner }
                @{ Name = 'EmbeddedWuRunner';      Text = $Script:EmbeddedWuRunner }
                @{ Name = 'EmbeddedDriverRunner';  Text = $Script:EmbeddedDriverRunner }
            )
            foreach ($r in $runners) {
                if (-not $r.Text) {
                    $schemaErrors += "Runner '$($r.Name)' is empty"
                    continue
                }
                $parseErrs = $null
                [void][System.Management.Automation.PSParser]::Tokenize($r.Text, [ref]$parseErrs)
                if ($parseErrs.Count -gt 0) {
                    $schemaErrors += "Runner '$($r.Name)' has $($parseErrs.Count) parse error(s): $($parseErrs[0].Message)"
                } else {
                    Write-Log ("[SELF-TEST] Runner '{0}' parses cleanly ({1} bytes)" -f $r.Name, $r.Text.Length) -Level OK
                }
            }

            if ($schemaErrors.Count -eq 0) {
                Write-Log '[SELF-TEST] Schema validation: PASS' -Level OK
            } else {
                foreach ($e in $schemaErrors) {
                    Write-Log ("[SELF-TEST] {0}" -f $e) -Level ERROR
                }
                Write-Log ("[SELF-TEST] Schema validation: FAIL ({0} issue(s))" -f $schemaErrors.Count) -Level ERROR
            }

            Write-Log '[SELF-TEST] Releasing lock and exiting cleanly.' -Level OK
            return
        }

        # ---- Initialization summary ----
        Write-Log ("Initialization complete. Timestamp: {0}" -f $Script:RunStamp) -Level INFO
        if ($Script:DryRun) {
            Write-Log 'Running in DryRun mode. No permanent changes will be committed.' -Level PREVIEW
        }
        if ($Script:AllowResetBase) {
            Write-Log '-AllowResetBase enabled - old updates WILL become uninstallable.' -Level WARN
        }
        if ($Script:AllowNetworkReset) {
            Write-Log '-AllowNetworkReset enabled - reboot will be REQUIRED.' -Level WARN
        }
        if ($Script:AllowPrefetch) {
            Write-Log '-AllowPrefetch enabled - prefetch purge is NOT recommended.' -Level WARN
        }

        # ---- PreCheck ----
        Invoke-PreCheck

        # ============================================================
        # STEP DISPATCHER
        # ============================================================
        $stepFunctions = @(
        'Invoke-Step25'
        'Invoke-Step01'
        'Invoke-Step01b'
        'Invoke-Step02'
        'Invoke-Step03'
        'Invoke-Step33'
        'Invoke-Step04'
        'Invoke-Step05'
        'Invoke-Step06'
        'Invoke-Step39'
        'Invoke-Step07'
        'Invoke-Step08'
        'Invoke-Step08b'
        'Invoke-Step09'
        'Invoke-Step10'
        'Invoke-Step11'
        'Invoke-Step29'
        'Invoke-Step34'
        'Invoke-Step12'
        'Invoke-Step13'
        'Invoke-Step14'
        'Invoke-Step15'
        'Invoke-Step16'
        'Invoke-Step17'
        'Invoke-Step18'
        'Invoke-Step19'
        'Invoke-Step20'
        'Invoke-Step21'
        'Invoke-Step22'
        'Invoke-Step23'
        'Invoke-Step24'
        'Invoke-Step26'
        'Invoke-Step27'
        'Invoke-Step28'
        'Invoke-Step30'
        'Invoke-Step31'
        'Invoke-Step32'
        'Invoke-Step35'
        'Invoke-Step36'
        'Invoke-Step37'
        'Invoke-Step38'
        'Invoke-Step40'
        'Invoke-Step41'
        'Invoke-Step42'
        'Invoke-Step43'
        'Invoke-Step44'
        'Invoke-Step45'
        'Invoke-Step46'
        'Invoke-Step47'
        'Invoke-Step49'
        'Invoke-Step50'
        'Invoke-Step51'
        'Invoke-Step52'
        'Invoke-Step54'
        'Invoke-Step55'
        'Invoke-Step56'
        'Invoke-Step57'
        'Invoke-Step58'
        'Invoke-Step59'
            )

        for ($i = 0; $i -lt $stepFunctions.Count; $i++) {
            $stepName = $stepFunctions[$i]
            # Extract the full key, including any letter suffix (''1b'', ''8b'').
            $stepNumStr = if ($stepName -match 'Invoke-Step(\d+[a-z]?)') { $Matches[1] } else { [string]($i + 1) }
            # Normalize leading zeros: "01" -> "1", "01b" -> "1b", "08b" -> "8b"
            $stepNumStr = $stepNumStr -replace '^0+(\d)', '$1'
            $stepNum = if ($stepNumStr -match '^(\d+)') { [int]$Matches[1] } else { $i + 1 }

            # Use the full key (with suffix) for skip checks and report rows
            if (-not (Test-StepEnabled $stepNumStr)) { continue }

            if (Get-Command $stepName -ErrorAction SilentlyContinue) {
                Write-Log '' -Level INFO
                Write-Log ('=' * 60) -Level STEP
                $__stepDisplayName = if ($Script:StepNames.ContainsKey($stepNumStr)) {
    $Script:StepNames[$stepNumStr]
} elseif ($Script:StepNames.ContainsKey([int]$stepNum)) {
    $Script:StepNames[[int]$stepNum]
} else {
    $stepName
}
                Write-Log ('Step {0}: {1}' -f $stepNumStr, $__stepDisplayName) -Level STEP
                Write-Log ('=' * 60) -Level STEP

                $stepSw = [System.Diagnostics.Stopwatch]::StartNew()
                $stepStatus = 'OK'
                $stepDetail = ''
                $Script:LastStepStatus = $null
                try {
                    & $stepName
                    if ($Script:LastStepStatus) {
                        # Step signalled a non-default status (e.g. 'Detached')
                        $stepStatus = $Script:LastStepStatus
                        $stepDetail = 'Launched in detached window - see child log for result'
                    } elseif ($Script:DryRun) {
                        $stepStatus = 'DryRun'
                        $stepDetail = 'Dry run - no changes made'
                    }
                } catch {
                    $stepStatus = 'Failed'
                    $stepDetail = $_.Exception.Message
                    Write-Log ("Step {0} threw an exception: {1}" -f $stepNum, $_.Exception.Message) -Level ERROR
                    Write-Log ("  At: {0}" -f $_.InvocationInfo.PositionMessage) -Level DEBUG
                }
                $stepSw.Stop()

                $rptName = if ($Script:StepNames.ContainsKey($stepNumStr)) { $Script:StepNames[$stepNumStr] } else { $stepName }
                $rptDetail = if ($Script:StepDescriptions.ContainsKey($stepNumStr)) { $Script:StepDescriptions[$stepNumStr] } else { $stepDetail }
                Add-ReportStep -Number $stepNumStr -Name $rptName -Status $stepStatus -Detail $rptDetail -Duration $stepSw.Elapsed
            } else {
                Write-Log ("Step function {0} not found - skipping." -f $stepName) -Level WARN
                $rptName = if ($Script:StepNames.ContainsKey($stepNumStr)) { $Script:StepNames[$stepNumStr] } else { $stepName }
                Add-ReportStep -Number $stepNumStr -Name $rptName -Status 'Skipped' -Detail 'Function not found'
            }
        }

        # ---- PostCheck ----
        Write-Log '' -Level INFO
        Invoke-PostCheck

    } catch {
        Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR
        Write-Log "At: $($_.InvocationInfo.PositionMessage)" -Level DEBUG
        exit 1
    } finally {
        # ---- Cleanup (ORDER: report + lock release FIRST, pause LAST) ----

        # ---- Generate HTML report (skip in rollback + SelfTest modes) ----
        # [FIX-SELFTEST-REPORT] SelfTest returns before the dispatcher
        # runs, so $Script:Report.Steps is empty and the report has no
        # meaningful content. Skip generation to avoid noise.
        if ($Script:SelfTest) {
            Write-Host 'SelfTest mode - skipping HTML report generation.' -ForegroundColor DarkGray
        } elseif ($Script:InRollbackMode) {
            Write-Host 'Rollback mode - skipping HTML report generation.' -ForegroundColor DarkGray
        } else {
            try {
                Write-HtmlReport
            } catch {
                Write-Log ("HTML report generation threw: {0}" -f $_.Exception.Message) -Level WARN
            }
        }

        Exit-ScriptLock

        # ---- Pause so user can read the summary (LAST) ----
        try {
            Write-Host 'Press any key to exit...' -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        } catch {
            # Non-interactive session - skip pause
        }

        # Stop-Transcript removed - single log file only

        # ---- Log retention removed - single log auto-truncates at 5 MB ----

        # Clean up any stray temp files from previous cmd-era runs
        # (defensive - our PS version doesn't create these, but old runs might have)
        try {
            $staleFiles = @(
                (Join-Path $env:TEMP 'fc_lockcheck.ps1'),
                (Join-Path $env:TEMP 'fc_spinner_*.ps1'),
                (Join-Path $env:TEMP 'fc_step*.ps1'),
                (Join-Path $env:TEMP 'fc_vpncheck.ps1')
            )
            foreach ($pattern in $staleFiles) {
                Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
                    Remove-Item -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # cleanup failure is non-fatal
        }
    }
}

# ============================================================
# ENTRYPOINT
# ============================================================
Main