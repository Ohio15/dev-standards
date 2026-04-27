@echo off
REM Windows Task Scheduler wrapper for npm-audit-weekly.sh.
REM Avoids the quoting issue when schtasks /TR contains a path with spaces.
"C:\Program Files\Git\bin\bash.exe" "D:/Projects/dev-standards/scripts/npm-audit-weekly.sh" --root D:/Projects --brain-store
