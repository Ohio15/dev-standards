# register-hygiene-task.ps1 - (re)register the Windows scheduled task
# DevStandards-HygieneScan (Sunday 05:00) that runs hygiene-scan-task.ps1.
#
# Idempotent: an existing task of the same name is replaced. Settings that the
# hand-typed schtasks line in the old README got wrong:
#   -StartWhenAvailable  a Sunday 05:00 missed because the PC was off or nobody
#                        was logged on now runs at the next opportunity. Without
#                        it the task silently skipped 2026-06-21..08-02 and
#                        2026-09-06..09-20 (no reports exist for those weeks).
#   -LogonType S4U       (default) runs whether or not a desktop session is
#                        open, like Cortex-SecurityAudit-*. Registering S4U
#                        needs an ELEVATED PowerShell; pass -LogonType
#                        Interactive to register unelevated (then the task only
#                        runs while Ron is logged on, and catches up at logon).
#
# ASCII ONLY (Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI).
param(
    [ValidateSet('S4U', 'Interactive')][string]$LogonType = 'S4U',
    [switch]$Unregister
)
$ErrorActionPreference = 'Stop'
$name = 'DevStandards-HygieneScan'
$wrapper = Join-Path $PSScriptRoot 'hygiene-scan-task.ps1'
$checkout = Split-Path -Parent $PSScriptRoot
$ps = (Get-Command powershell.exe -ErrorAction Stop).Source

if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
    Write-Output "removed existing task $name"
}
if ($Unregister) { exit 0 }

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType $LogonType -RunLevel Limited
$action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wrapper`" --root D:/Projects --brain-store" -WorkingDirectory $checkout
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 05:00
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'Weekly repo hygiene scan (dev-standards scripts/repo-hygiene-scan.py via hygiene-scan-task.ps1). Log: ~/scans/hygiene-<date>.log. Non-zero result = the scan did not do its job; findings alone exit 0.' | Out-Null
Write-Output "registered $name (Sunday 05:00, $LogonType, StartWhenAvailable)"
