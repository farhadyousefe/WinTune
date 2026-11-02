#Requires -Version 5.1
<#
.SYNOPSIS
    Makes every public GitHub repo in your account private, except a keep-list.

.DESCRIPTION
    Uses the `gh` CLI to enumerate your public repos and flip each one's
    visibility to private. A keep-list (default: WinTune) is preserved
    as public.

    The script:
      1. Verifies `gh` is installed and authenticated
      2. Lists every public repo that WILL be made private
      3. Asks for explicit confirmation
      4. Runs `gh repo edit --visibility private` per repo
      5. Reports success/failure per repo

.PARAMETER KeepPublic
    Array of repo names to keep public. Default: @('WinTune').

.PARAMETER Owner
    GitHub username or org. Defaults to the authenticated user.

.PARAMETER DryRun
    Only list what would change. Don't touch anything.

.EXAMPLE
    .\Make-Repos-Private.ps1 -DryRun
    Preview which repos would be made private.

.EXAMPLE
    .\Make-Repos-Private.ps1
    Apply the change (with confirmation prompt).
#>

[CmdletBinding()]
param(
    [string[]]$KeepPublic = @('WinTune'),
    [string]$Owner = '',
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' GitHub Repository Privacy Sweep' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''

# ---- 1. Verify gh is available ----
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Host '[FAIL] gh CLI not found. Install from https://cli.github.com/' -ForegroundColor Red
    exit 1
}

# ---- 2. Verify gh is authenticated ----
try {
    $authStatus = & gh auth status 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[FAIL] gh is not authenticated. Run: gh auth login' -ForegroundColor Red
        Write-Host $authStatus
        exit 1
    }
} catch {
    Write-Host ('[FAIL] Could not check gh auth status: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}

# ---- 3. Determine owner ----
if (-not $Owner) {
    try {
        $Owner = (& gh api user --jq '.login' 2>$null).Trim()
    } catch {
        Write-Host '[FAIL] Could not determine GitHub username. Pass -Owner explicitly.' -ForegroundColor Red
        exit 1
    }
}

Write-Host ('Owner:  {0}' -f $Owner)
Write-Host ('Keep:   {0}' -f ($KeepPublic -join ', '))
Write-Host ('Mode:   {0}' -f $(if ($DryRun) { 'DRY RUN' } else { 'LIVE (will prompt)' }))
Write-Host ''

# ---- 4. Enumerate public repos ----
Write-Host 'Enumerating public repositories...' -ForegroundColor Gray

$allRepos = @()
try {
    $json = & gh repo list $Owner --limit 1000 --json name,visibility,isFork,stargazerCount --jq '.[]' 2>&1
    foreach ($line in $json) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $allRepos += ($line | ConvertFrom-Json)
        } catch { }
    }
} catch {
    Write-Host ('[FAIL] Could not list repos: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}

# ---- 5. Classify ----
$toMakePrivate = @()
$toKeep        = @()

foreach ($repo in $allRepos) {
    if ($repo.visibility -ne 'PUBLIC') { continue }

    if ($KeepPublic -contains $repo.name) {
        $toKeep += $repo
    } else {
        $toMakePrivate += $repo
    }
}

# ---- 6. Show plan ----
Write-Host ''
Write-Host '--- KEEP PUBLIC ---' -ForegroundColor Green
if ($toKeep.Count -eq 0) {
    Write-Host '  (none)' -ForegroundColor DarkGray
} else {
    foreach ($r in $toKeep) {
        Write-Host ('  [KEEP]    {0}  ({1} stars)' -f $r.name, $r.stargazerCount) -ForegroundColor Green
    }
}

Write-Host ''
Write-Host '--- WILL MAKE PRIVATE ---' -ForegroundColor Yellow
if ($toMakePrivate.Count -eq 0) {
    Write-Host '  (none - nothing to do)' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'All public repos are already in your keep-list. Done.' -ForegroundColor Green
    exit 0
} else {
    foreach ($r in $toMakePrivate | Sort-Object name) {
        $forkTag = if ($r.isFork) { ' [fork]' } else { '' }
        Write-Host ('  [PRIVATE] {0}  ({1} stars){2}' -f $r.name, $r.stargazerCount, $forkTag) -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host ('Total: {0} will be made private, {1} kept public.' -f $toMakePrivate.Count, $toKeep.Count) -ForegroundColor Cyan

if ($DryRun) {
    Write-Host ''
    Write-Host '[DRY RUN] No changes made. Re-run without -DryRun to apply.' -ForegroundColor Magenta
    exit 0
}

# ---- 7. Confirm ----
Write-Host ''
Write-Host 'WARNING: Making a repo private will:' -ForegroundColor Yellow
Write-Host '  - Hide it from search engines and non-collaborators' -ForegroundColor Yellow
Write-Host '  - Break any existing links to the repo (GitHub returns 404)' -ForegroundColor Yellow
Write-Host '  - Preserve stars, forks, and issues internally' -ForegroundColor Yellow
Write-Host '  - Keep the same URL (github.com/OWNER/REPO)' -ForegroundColor Yellow
Write-Host '  - Allow reversal at any time (Settings -> Danger Zone)' -ForegroundColor Yellow
Write-Host ''

$confirm = Read-Host ('Type "yes" to make {0} repo(s) private' -f $toMakePrivate.Count)
if ($confirm.Trim().ToLowerInvariant() -ne 'yes') {
    Write-Host 'Aborted. No changes made.' -ForegroundColor Gray
    exit 0
}

# ---- 8. Apply ----
Write-Host ''
Write-Host 'Applying visibility changes...' -ForegroundColor Cyan

$okCount = 0
$failCount = 0
$failed = @()

foreach ($repo in $toMakePrivate | Sort-Object name) {
    Write-Host ('  [{0}] -> private' -f $repo.name) -ForegroundColor Gray -NoNewline

    try {
        $result = & gh repo edit "$Owner/$($repo.name)" `
                    --visibility private `
                    --accept-visibility-change-consequences 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host '  OK' -ForegroundColor Green
            $okCount++
        } else {
            Write-Host ('  FAIL: {0}' -f ($result -join ' ').Trim()) -ForegroundColor Red
            $failCount++
            $failed += $repo.name
        }
    } catch {
        Write-Host ('  FAIL: {0}' -f $_.Exception.Message) -ForegroundColor Red
        $failCount++
        $failed += $repo.name
    }
}

# ---- 9. Summary ----
Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host (' DONE: {0} made private, {1} failed' -f $okCount, $failCount) -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan

if ($failCount -gt 0) {
    Write-Host ''
    Write-Host 'Failed repos (fix manually):' -ForegroundColor Yellow
    foreach ($name in $failed) {
        Write-Host ('  - https://github.com/{0}/{1}/settings' -f $Owner, $name) -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host 'Common causes:' -ForegroundColor Gray
    Write-Host '  - Repo has forks with stars that prevent visibility change' -ForegroundColor Gray
    Write-Host '  - Organization policy restricts visibility' -ForegroundColor Gray
    Write-Host '  - gh token lacks "repo" scope' -ForegroundColor Gray
    exit 1
}

Write-Host ''
Write-Host 'Done. Verify at:' -ForegroundColor Green
Write-Host ('  https://github.com/{0}?tab=repositories' -f $Owner) -ForegroundColor Gray
