@echo off
setlocal enabledelayedexpansion
REM ============================================================================
REM Windows Vulnerability Scan Preparation - CMD/Batch Script
REM
REM Purpose: Prepare Windows machine for credentialed vulnerability scanning
REM Run As Administrator
REM
REM Usage:
REM   Interactive mode:  Prepare-WindowsForVulnScan.cmd
REM   Automated mode:    Prepare-WindowsForVulnScan.cmd AUTO
REM
REM Passing AUTO as the first argument suppresses all interactive prompts
REM (restart prompt, final pause). Use this when the script is invoked via
REM WinRM from Deploy-ScanPrepToMultiple.ps1 to prevent indefinite stdin hang.
REM ============================================================================

REM ============================================================================
REM AUTO MODE DETECTION
REM
REM BUG FIX #5 - Interactive restart prompt hangs in automated WinRM deployment.
REM The original script ended with "set /p restart=..." which blocks forever
REM when stdin is not attached (i.e. when called via Invoke-Command over WinRM).
REM Fix: Detect AUTO argument and bypass all interactive prompts + pause calls.
REM ============================================================================
set AUTOMODE=0
if /i "%~1"=="AUTO" set AUTOMODE=1

echo.
echo ============================================================================
echo Windows Scan Preparation Script (CMD Version)
echo ============================================================================
echo.
if "%AUTOMODE%"=="1" echo [AUTO MODE] Running non-interactively - all prompts suppressed
echo.

REM ============================================================================
REM ADMINISTRATOR CHECK
REM ============================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo         Please right-click and select "Run as Administrator".
    if "%AUTOMODE%"=="0" pause
    exit /b 1
)
echo [OK] Administrator privileges confirmed

REM ============================================================================
REM LOG FILE SETUP
REM
REM BUG FIX #1 - Locale-dependent date/time parsing in log filename.
REM The original code used:
REM   for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set mydate=%%c%%a%%b)
REM   for /f "tokens=1-2 delims=/:" %%a in ('time /t') do (set mytime=%%a%%b)
REM "date /t" output is fully locale-dependent. On DD/MM/YYYY systems (APAC,
REM most of EU) the token positions are wrong, producing filenames like:
REM   VulnScanPrep__AM.log  (completely empty date, only AM/PM suffix)
REM Fix: Delegate timestamp generation to PowerShell, which always returns
REM yyyyMMdd_HHmmss regardless of Windows regional settings.
REM ============================================================================
for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "Get-Date -Format 'yyyyMMdd_HHmmss'"`) do set TIMESTAMP=%%T
set LOGFILE=C:\Windows\Temp\VulnScanPrep_%TIMESTAMP%.log
set BACKUP_DIR=C:\Windows\Temp

echo Starting configuration
echo Log file: %LOGFILE%
echo.
echo %date% %time% - Script started [AutoMode=%AUTOMODE%] >> "%LOGFILE%"

REM ============================================================================
REM REGISTRY BACKUP
REM
REM BUG FIX #4 - No registry backup in the CMD version.
REM The original CMD script made absolutely no backup of the registry keys it
REM modifies. The PS1 version at least attempted one (though it was broken).
REM Fix: Export both affected registry subtrees before modification using
REM "reg export". Backups are timestamped and placed in the same temp directory
REM as the log file for easy retrieval.
REM ============================================================================
echo.
echo === BACKING UP REGISTRY KEYS ===
echo. >> "%LOGFILE%"
echo === BACKING UP REGISTRY KEYS === >> "%LOGFILE%"

echo Exporting Policies\System registry key...
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "%BACKUP_DIR%\VulnScanPrep_%TIMESTAMP%_Policies_System.reg" /y >> "%LOGFILE%" 2>&1
if %errorlevel% equ 0 (
    echo [OK] Policies\System backed up to %BACKUP_DIR%\VulnScanPrep_%TIMESTAMP%_Policies_System.reg
    echo [OK] Policies\System backup succeeded >> "%LOGFILE%"
) else (
    echo [WARNING] Could not back up Policies\System - proceeding anyway
    echo [WARNING] Policies\System backup failed >> "%LOGFILE%"
)

echo Exporting LanmanServer\Parameters registry key...
reg export "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "%BACKUP_DIR%\VulnScanPrep_%TIMESTAMP%_LanmanServer.reg" /y >> "%LOGFILE%" 2>&1
if %errorlevel% equ 0 (
    echo [OK] LanmanServer\Parameters backed up to %BACKUP_DIR%\VulnScanPrep_%TIMESTAMP%_LanmanServer.reg
    echo [OK] LanmanServer\Parameters backup succeeded >> "%LOGFILE%"
) else (
    echo [WARNING] Could not back up LanmanServer\Parameters - proceeding anyway
    echo [WARNING] LanmanServer\Parameters backup failed >> "%LOGFILE%"
)

REM ============================================================================
REM ENABLE SERVICES
REM
REM BUG FIX #2 - Incorrect service start error handling.
REM The original code ran "net start <service>" and checked errorlevel, but:
REM   - Exit code 0 = service started successfully
REM   - Exit code 2 = "The service has already been started" (not an error)
REM   - Exit code 1 = genuine failure
REM Both non-zero codes produced the same "[!] might already be running"
REM message, making genuine start failures invisible to the operator.
REM Fix: Use "sc query <service> | find RUNNING" BEFORE attempting "net start".
REM This clearly separates three distinct states:
REM   1. Already running   -> [OK] Already running (no action needed)
REM   2. Not running       -> attempt net start, check errorlevel for real failure
REM   3. sc config failure -> [WARNING] startup type could not be set
REM ============================================================================
echo.
echo === ENABLING SERVICES ===
echo. >> "%LOGFILE%"
echo === ENABLING SERVICES === >> "%LOGFILE%"

REM --- WMI Service (Winmgmt) ---
echo Configuring WMI Service (Winmgmt)...
sc config Winmgmt start= auto >> "%LOGFILE%" 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Could not set Winmgmt startup type to Automatic
    echo [WARNING] sc config Winmgmt failed >> "%LOGFILE%"
)

sc query Winmgmt | find "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] WMI service is already running
    echo [OK] Winmgmt already running >> "%LOGFILE%"
) else (
    net start Winmgmt >> "%LOGFILE%" 2>&1
    if %errorlevel% equ 0 (
        echo [OK] WMI service started successfully
        echo [OK] Winmgmt started >> "%LOGFILE%"
    ) else (
        echo [ERROR] Failed to start WMI service - check log for details
        echo [ERROR] net start Winmgmt failed >> "%LOGFILE%"
    )
)

REM --- Remote Registry ---
echo Configuring Remote Registry (RemoteRegistry)...
sc config RemoteRegistry start= auto >> "%LOGFILE%" 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Could not set RemoteRegistry startup type to Automatic
    echo [WARNING] sc config RemoteRegistry failed >> "%LOGFILE%"
)

sc query RemoteRegistry | find "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Remote Registry service is already running
    echo [OK] RemoteRegistry already running >> "%LOGFILE%"
) else (
    net start RemoteRegistry >> "%LOGFILE%" 2>&1
    if %errorlevel% equ 0 (
        echo [OK] Remote Registry service started successfully
        echo [OK] RemoteRegistry started >> "%LOGFILE%"
    ) else (
        echo [ERROR] Failed to start Remote Registry service - check log for details
        echo [ERROR] net start RemoteRegistry failed >> "%LOGFILE%"
    )
)

REM --- Windows Remote Management (WinRM) ---
echo Configuring Windows Remote Management (WinRM)...
sc config WinRM start= auto >> "%LOGFILE%" 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Could not set WinRM startup type to Automatic
    echo [WARNING] sc config WinRM failed >> "%LOGFILE%"
)

sc query WinRM | find "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] WinRM service is already running
    echo [OK] WinRM already running >> "%LOGFILE%"
) else (
    net start WinRM >> "%LOGFILE%" 2>&1
    if %errorlevel% equ 0 (
        echo [OK] WinRM service started successfully
        echo [OK] WinRM started >> "%LOGFILE%"
    ) else (
        echo [ERROR] Failed to start WinRM service - check log for details
        echo [ERROR] net start WinRM failed >> "%LOGFILE%"
    )
)

REM ============================================================================
REM DISABLE UAC REMOTE RESTRICTIONS
REM ============================================================================
echo.
echo === DISABLING UAC REMOTE RESTRICTIONS ===
echo. >> "%LOGFILE%"
echo === DISABLING UAC REMOTE RESTRICTIONS === >> "%LOGFILE%"

echo Setting LocalAccountTokenFilterPolicy...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f >> "%LOGFILE%" 2>&1
if %errorlevel% equ 0 (
    echo [OK] LocalAccountTokenFilterPolicy set to 1
    echo [OK] LocalAccountTokenFilterPolicy set >> "%LOGFILE%"
) else (
    echo [ERROR] Failed to set LocalAccountTokenFilterPolicy
    echo [ERROR] LocalAccountTokenFilterPolicy reg add failed >> "%LOGFILE%"
)

REM ============================================================================
REM ENABLE FIREWALL RULES
REM
REM BUG FIX #3 - Locale-dependent firewall rule display names.
REM The original code used:
REM   netsh advfirewall firewall set rule name="Windows Management
REM   Instrumentation (WMI-In)" new enable=yes
REM The "name=" parameter matches the DISPLAY name of the rule, which is fully
REM localized on non-English Windows. On German Windows the same rule is named
REM "Windows-Verwaltungsinstrumentierung (WMI eingehend)". The netsh command
REM silently exits 0 even when no matching rule is found, giving the operator
REM false confidence on every non-English deployment in APAC and EU.
REM
REM Fix: Replace netsh with an inline PowerShell call using Enable-NetFirewallRule.
REM Two complementary strategies are used for maximum compatibility:
REM   Strategy A - Enable by internal rule Name (locale-independent stable ID):
REM     The "Name" property of Get-NetFirewallRule is a fixed internal identifier
REM     that does NOT change with the Windows display language. These names are
REM     consistent across all language packs.
REM   Strategy B - Enable by DisplayGroup keyword match (belt-and-suspenders):
REM     Falls back to pattern-matching on DisplayGroup containing "WMI" or
REM     "File and Printer Sharing" keywords. These abbreviations are retained
REM     even in localized group names (e.g. DE still includes "WMI").
REM A temporary .ps1 is used to avoid CMD shell quoting conflicts with
REM PowerShell scriptblock syntax inside a single -Command string.
REM ============================================================================
echo.
echo === ENABLING FIREWALL RULES (locale-independent) ===
echo. >> "%LOGFILE%"
echo === ENABLING FIREWALL RULES === >> "%LOGFILE%"

set _FWSCRIPT=%TEMP%\_VulnScanFW_%TIMESTAMP%.ps1

REM Write the firewall PS1 using per-line echo >> to avoid CMD block-paren conflicts
echo $ErrorActionPreference = 'SilentlyContinue' > "%_FWSCRIPT%"
echo $wmiNames = @('WMI-WINMGMT-In-TCP-NoScope','WMI-WINMGMT-In-TCP','WMI-ASYNC-In-TCP-NoScope','WMI-ASYNC-In-TCP') >> "%_FWSCRIPT%"
echo $smbNames = @('FPS-SMB-In-TCP','FPS-NB-Session-In-TCP') >> "%_FWSCRIPT%"
echo # Strategy A: enable by stable internal Name (locale-independent) >> "%_FWSCRIPT%"
echo ($wmiNames + $smbNames) ^| ForEach-Object { >> "%_FWSCRIPT%"
echo     $r = Get-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue >> "%_FWSCRIPT%"
echo     if ($r) { Enable-NetFirewallRule -Name $_; Write-Output "[FW-OK-A] Enabled by Name: $_" } >> "%_FWSCRIPT%"
echo     else    { Write-Warning "[FW-SKIP-A] Internal name not found on this OS version: $_" } >> "%_FWSCRIPT%"
echo } >> "%_FWSCRIPT%"
echo # Strategy B: fallback - enable by DisplayGroup keyword match >> "%_FWSCRIPT%"
echo Get-NetFirewallRule -Direction Inbound ^| Where-Object { $_.DisplayGroup -match 'WMI' } ^| >> "%_FWSCRIPT%"
echo     ForEach-Object { Enable-NetFirewallRule -Name $_.Name; Write-Output "[FW-OK-B] WMI group: $($_.DisplayName)" } >> "%_FWSCRIPT%"
echo Get-NetFirewallRule -Direction Inbound ^| Where-Object { $_.DisplayGroup -match 'File.+Print' } ^| >> "%_FWSCRIPT%"
echo     ForEach-Object { Enable-NetFirewallRule -Name $_.Name; Write-Output "[FW-OK-B] Sharing group: $($_.DisplayName)" } >> "%_FWSCRIPT%"
echo Write-Output "[FW] Firewall enablement completed" >> "%_FWSCRIPT%"

echo Enabling WMI and File Sharing firewall rules...
powershell -ExecutionPolicy Bypass -NoProfile -File "%_FWSCRIPT%" >> "%LOGFILE%" 2>&1
if %errorlevel% equ 0 (
    echo [OK] Firewall rules configured - see log for per-rule details
) else (
    echo [WARNING] PowerShell firewall script returned non-zero - check log
)
del "%_FWSCRIPT%" >nul 2>&1

REM ============================================================================
REM ENABLE ADMIN SHARES
REM ============================================================================
echo.
echo === ENABLING ADMIN SHARES ===
echo. >> "%LOGFILE%"
echo === ENABLING ADMIN SHARES === >> "%LOGFILE%"

echo Enabling AutoShareServer (admin shares C$, ADMIN$, IPC$)...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 1 /f >> "%LOGFILE%" 2>&1
if %errorlevel% equ 0 (
    echo [OK] Admin shares (C$, ADMIN$, IPC$) enabled
    echo [OK] AutoShareServer set to 1 >> "%LOGFILE%"
) else (
    echo [ERROR] Failed to enable admin shares
    echo [ERROR] AutoShareServer reg add failed >> "%LOGFILE%"
)

REM ============================================================================
REM CONFIGURE WINRM
REM ============================================================================
echo.
echo === CONFIGURING WINRM ===
echo. >> "%LOGFILE%"
echo === CONFIGURING WINRM === >> "%LOGFILE%"

echo Executing WinRM quickconfig...
winrm quickconfig -quiet >> "%LOGFILE%" 2>&1
if %errorlevel% equ 0 (
    echo [OK] WinRM configured successfully
    echo [OK] winrm quickconfig succeeded >> "%LOGFILE%"
) else (
    echo [OK] WinRM quickconfig returned non-zero (likely already configured - this is normal)
    echo [INFO] winrm quickconfig non-zero (may already be configured) >> "%LOGFILE%"
)

REM ============================================================================
REM VERIFICATION
REM ============================================================================
echo.
echo === VERIFICATION ===
echo. >> "%LOGFILE%"
echo === VERIFICATION === >> "%LOGFILE%"

echo Querying service states (full output in log)...
sc query Winmgmt      >> "%LOGFILE%" 2>&1
sc query RemoteRegistry >> "%LOGFILE%" 2>&1
sc query WinRM        >> "%LOGFILE%" 2>&1

echo Services currently running:
net start | find /i "Windows Management Instrumentation"
net start | find /i "Remote Registry"
net start | find /i "Windows Remote Management"

echo.
echo Registry value verification:
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy 2>&1 | find "LocalAccountTokenFilterPolicy"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer 2>&1 | find "AutoShareServer"

REM ============================================================================
REM COMPLETION AND RESTART
REM
REM BUG FIX #5 (continued) - Final "pause" also hangs in automated mode.
REM The original script had both "set /p restart=..." and a trailing "pause",
REM both of which block indefinitely when stdin is not a terminal (WinRM context).
REM Fix: In AUTO mode, skip restart prompt and pause entirely, exit /b 0 cleanly.
REM The calling Deploy-ScanPrepToMultiple.ps1 handles restart orchestration
REM centrally via Restart-Machines / shutdown /r, so no restart action is needed
REM from this script when AUTO is set.
REM ============================================================================
echo.
echo ============================================================================
echo Configuration Complete
echo ============================================================================
echo.
echo IMPORTANT: A system restart is recommended for all changes to take effect.
echo Log file    : %LOGFILE%
echo Reg backups : %BACKUP_DIR%\VulnScanPrep_%TIMESTAMP%_*.reg
echo.
echo %date% %time% - Configuration steps completed >> "%LOGFILE%"

if "%AUTOMODE%"=="1" (
    echo [AUTO MODE] Skipping restart prompt.
    echo             Orchestrate restart from the calling deployment script.
    echo [AUTO MODE] Script exiting cleanly >> "%LOGFILE%"
    exit /b 0
)

REM --- Interactive path only (AUTOMODE=0) ---
set /p restart="Restart now? (Y/N): "
if /i "%restart%"=="Y" (
    echo Scheduling restart in 60 seconds...
    echo %date% %time% - User requested restart >> "%LOGFILE%"
    shutdown /r /t 60 /c "Restarting for vulnerability scan configuration"
) else (
    echo Please restart this machine manually before running the vulnerability scan.
    echo %date% %time% - User deferred restart >> "%LOGFILE%"
)

echo %date% %time% - Script completed >> "%LOGFILE%"
pause
endlocal
