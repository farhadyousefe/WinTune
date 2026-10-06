# WinTune

A comprehensive Windows 10/11 maintenance suite in a single PowerShell script.
55 steps covering cleanup, performance tuning, system repair, diagnostics, and
security hardening.

## Requirements

- Windows 10 build 19041 (20H1) or later, or Windows 11
- PowerShell 5.1 (built into Windows) or PowerShell 7+
- Administrator privileges

## Quick Start

    .\WinTune.ps1 -DryRun    # preview, makes no changes
    .\WinTune.ps1            # full maintenance run

Or double-click `WinTune.bat` for a full automated run.

## What It Does

**Cleanup** - system temp, Windows Update cache, Delivery Optimization cache,
recycle bins, browser caches, Office/Outlook temp, PDF reader caches, VS Code,
Teams, Copilot, thumbnail caches, broken shortcuts.

**Performance** - telemetry tuning, taskbar/Game DVR, power plan, visual
effects, Storage Sense, SysMain on SSDs, Delivery Optimization LAN-only,
TCP performance tuning.

**Repair** - DISM CheckHealth, SFC /scannow, DISM RestoreHealth (gated),
component store cleanup. All run in a detached visible window with live
progress and stall detection.

**Diagnostics** - event logs, VSS cap, DriverStore audit, startup audit,
scheduled tasks audit, WAL detection, context menu audit, orphaned
program registry cleanup.

**Security** - SMBv1 disable, LLMNR/WPAD disable, DNS over HTTPS,
Defender ASR rules (Audit Mode), AutoRun disable.

**Updates** - Winget upgrades with auto-install, Windows Update with silent
PSWindowsUpdate install, driver updates (firmware excluded), feature update
deferral.

## Flags

| Flag | Purpose |
|---|---|
| `-DryRun` | Preview everything, make no changes |
| `-AllowResetBase` | Permits the irreversible DISM `/ResetBase` |
| `-AllowNetworkReset` | Permits Winsock/TCP-IP reset (requires reboot) |
| `-AllowPrefetch` | Permits Prefetch purge (not recommended) |
| `-AllowWinget` | Launches detached winget upgrade runner |
| `-InstallUpdates` | Launches detached Windows Update runner |
| `-AllowDriverUpdates` | Installs eligible driver updates |
| `-AllowDismRestore` | Permits DISM RestoreHealth |
| `-YesToAll` | Auto-answers Y to all prompts |
| `-SkipSteps 1,12,13` | Skips specific steps |

See `Get-Help .\WinTune.ps1 -Full` for the complete list.

## Safety

WinTune creates a System Restore point as the first action of every run.
Roll back via Start -> "Create a restore point" -> System Restore -> select
"WinTune_PreChange".

Registry modifications write timestamped `.reg` backups under
`RegistryBackups\`. Service changes write entries to
`Rollback_<timestamp>.jsonl` that can be reverted with `-Rollback`.

## License

MIT - see [LICENSE](LICENSE).
