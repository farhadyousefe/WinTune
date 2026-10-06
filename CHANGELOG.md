# Changelog

All notable changes to WinTune are documented here.

## [1.0.0] - 2026-10-06

First public release.

### Features

- 55-step Windows maintenance suite (cleanup, performance, repair, diagnostics, security, updates)
- Detached runner architecture for SFC/DISM, Winget, Windows Update, and Driver Updates
- Live progress with spinner, timer, and stall detection in every runner
- Pre-change System Restore point created as the first action of every run
- Registry backups and rollback manifest support
- Self-contained HTML run report after every run

### Fixed

- Winget upgrade no longer overrides package pins (removed --force)
- SFC no longer floods console with Verification N% complete lines
- DISM no longer matches stale lines from prior sessions
- Timer no longer wraps at 60 minutes
- Stall detection shows [stalled Ns] when a download hangs
- All backtick line continuations removed for PowerShell 5.1 compatibility
- Mojibake in em-dash characters corrected

### Requirements

- Windows 10 19041 (20H1) or Windows 11
- PowerShell 5.1 or PowerShell 7+
- Administrator privileges
