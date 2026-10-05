@echo off
REM Windows Task Scheduler wrapper for npm-audit-weekly.sh.
REM Avoids the quoting issue when schtasks /TR contains a path with spaces.
REM The .sh is resolved next to this file (%~dp0), never from a hard-coded repo path:
REM the 2026-08 D:\Projects restructure moved the repo and left this task exiting 127.
"C:\Program Files\Git\bin\bash.exe" "%~dp0npm-audit-weekly.sh" --root D:/Projects --brain-store
