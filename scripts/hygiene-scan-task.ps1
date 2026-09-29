# hygiene-scan-task.ps1 - Windows Task Scheduler entry point for the weekly
# repo hygiene scan (scheduled task DevStandards-HygieneScan, registered by
# register-hygiene-task.ps1). The Windows counterpart of hygiene-scan-cron.sh.
#
# WHY A WRAPPER. repo-hygiene-scan.py exits 1/2 when it FINDS MEDIUM/HIGH
# issues. Task Scheduler reports that as a failed run, so a scan that worked
# and a scan that crashed looked identical (LastTaskResult 2 on 2026-09-27 was
# a successful scan that found a HIGH). This wrapper keeps the two apart:
#
#   task exit 0   the scan ran; findings (any severity) are in the JSON report,
#                 the brain-store memory and the log below
#   task exit N   the scan did NOT do its job: 3 = brain-store failed,
#                 70 = scanner crash, anything else = unexpected; see the log
#
# Every run writes ~/scans/hygiene-<yyyy-MM-dd>.log (stdout+stderr), headed by
# the checkout's branch/commit and its lag behind origin/main. The checkout is
# Ron's working tree, so it is NEVER pulled or switched here - a stale or
# off-main checkout is reported loudly in the log instead.
#
# All arguments are passed through to repo-hygiene-scan.py.
# ASCII ONLY (Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI).
$ErrorActionPreference = 'Stop'
$scanner = Join-Path $PSScriptRoot 'repo-hygiene-scan.py'
$checkout = Split-Path -Parent $PSScriptRoot
$scansDir = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'scans'
New-Item -ItemType Directory -Force -Path $scansDir | Out-Null
$log = Join-Path $scansDir ("hygiene-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))
function Log([string]$m) { Add-Content -LiteralPath $log -Value ("[{0}] {1}" -f (Get-Date -Format o), $m) }

try {
    $branch = (& git -C $checkout rev-parse --abbrev-ref HEAD 2>&1 | Out-String).Trim()
    $sha = (& git -C $checkout rev-parse --short HEAD 2>&1 | Out-String).Trim()
    & git -C $checkout fetch -q origin main 2>&1 | Out-Null
    $behind = (& git -C $checkout rev-list --count HEAD..origin/main 2>&1 | Out-String).Trim()
    Log "dev-standards checkout: branch=$branch head=$sha behind_origin_main=$behind"
    if ($branch -ne 'main' -or $behind -ne '0') {
        Log "WARNING: scanner is running from '$branch' ($behind behind origin/main), not current main"
    }
} catch {
    Log "WARNING: could not read checkout provenance: $($_.Exception.Message)"
}

$python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $python) { Log 'ABORT: python.exe not found on PATH'; exit 71 }
Log "running: $python $scanner $($args -join ' ')"
# Merge stderr into the log without letting PowerShell turn stderr lines into
# terminating errors under $ErrorActionPreference = 'Stop'.
$ErrorActionPreference = 'Continue'
& $python $scanner @args *>&1 | ForEach-Object { "$_" } | Add-Content -LiteralPath $log
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'

switch ($code) {
    0 { Log 'scan OK: no MEDIUM/HIGH findings'; exit 0 }
    1 { Log 'scan OK: highest finding MEDIUM (see report)'; exit 0 }
    2 { Log 'scan OK: highest finding HIGH (see report)'; exit 0 }
    3 { Log 'FAILED: scan ran but brain-store failed'; exit 3 }
    70 { Log 'FAILED: scanner crashed (traceback above)'; exit 70 }
    default { Log "FAILED: unexpected scanner exit $code"; exit $code }
}
