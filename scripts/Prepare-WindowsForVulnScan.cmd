@echo off
REM ============================================================================
REM Windows Vulnerability Scan Preparation - CMD/Batch Script
REM 
REM Purpose: Prepare Windows machine for credentialed vulnerability scanning
REM Run As Administrator
REM ============================================================================

REM Verify Administrator rights
echo.
echo ============================================================================
echo Windows Scan Preparation Script (CMD Version)
echo ============================================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script requires Administrator privileges
    echo Please run as Administrator
    pause
    exit /b 1
)

echo [OK] Administrator privileges confirmed
echo.

REM Log file
for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set mydate=%%c%%a%%b)
for /f "tokens=1-2 delims=/:" %%a in ('time /t') do (set mytime=%%a%%b)
set LOGFILE=C:\Windows\Temp\VulnScanPrep_%mydate%_%mytime%.log

echo Starting configuration - Log: %LOGFILE%
echo %date% %time% - Script started >> %LOGFILE%

REM ============================================================================
REM ENABLE SERVICES
REM ============================================================================

echo.
echo === ENABLING SERVICES ===
echo. >> %LOGFILE%
echo === ENABLING SERVICES === >> %LOGFILE%

REM Windows Management Instrumentation
echo Configuring WMI Service (Winmgmt)...
sc config Winmgmt start= auto >> %LOGFILE% 2>&1
net start Winmgmt >> %LOGFILE% 2>&1
if %errorlevel% equ 0 (
    echo [OK] WMI service enabled and started
) else (
    echo [!] WMI service might already be running
)

REM Remote Registry
echo Configuring Remote Registry (RemoteRegistry)...
sc config RemoteRegistry start= auto >> %LOGFILE% 2>&1
net start RemoteRegistry >> %LOGFILE% 2>&1
if %errorlevel% equ 0 (
    echo [OK] Remote Registry service enabled and started
) else (
    echo [!] Remote Registry service might already be running
)

REM Windows Remote Management (WinRM)
echo Configuring Windows Remote Management (WinRM)...
sc config WinRM start= auto >> %LOGFILE% 2>&1
net start WinRM >> %LOGFILE% 2>&1
if %errorlevel% equ 0 (
    echo [OK] WinRM service enabled and started
) else (
    echo [!] WinRM service might already be running
)

REM ============================================================================
REM DISABLE UAC REMOTE RESTRICTIONS
REM ============================================================================

echo.
echo === DISABLING UAC REMOTE RESTRICTIONS ===
echo. >> %LOGFILE%
echo === DISABLING UAC REMOTE RESTRICTIONS === >> %LOGFILE%

REM Set LocalAccountTokenFilterPolicy to 1
echo Setting LocalAccountTokenFilterPolicy...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f >> %LOGFILE% 2>&1
if %errorlevel% equ 0 (
    echo [OK] LocalAccountTokenFilterPolicy set to 1
) else (
    echo [!] Error setting LocalAccountTokenFilterPolicy
)

REM ============================================================================
REM ENABLE FIREWALL RULES
REM ============================================================================

echo.
echo === ENABLING FIREWALL RULES ===
echo. >> %LOGFILE%
echo === ENABLING FIREWALL RULES === >> %LOGFILE%

REM Note: netsh firewall commands are deprecated. Using advfirewall for Windows Vista+

echo Enabling WMI firewall rules...
netsh advfirewall firewall set rule name="Windows Management Instrumentation (WMI-In)" new enable=yes >> %LOGFILE% 2>&1
netsh advfirewall firewall set rule name="Windows Management Instrumentation (WINMGMT-In)" new enable=yes >> %LOGFILE% 2>&1
netsh advfirewall firewall set rule name="Windows Management Instrumentation (ASYNC-In)" new enable=yes >> %LOGFILE% 2>&1

REM Enable SMB/File Sharing rules
echo Enabling File and Printer Sharing rules...
netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" new enable=yes >> %LOGFILE% 2>&1
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=yes >> %LOGFILE% 2>&1

echo [OK] Firewall rules configured

REM ============================================================================
REM ENABLE ADMIN SHARES
REM ============================================================================

echo.
echo === ENABLING ADMIN SHARES ===
echo. >> %LOGFILE%
echo === ENABLING ADMIN SHARES === >> %LOGFILE%

REM Enable AutoShareServer (enables C$, ADMIN$, IPC$ shares)
echo Enabling AutoShareServer (admin shares)...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 1 /f >> %LOGFILE% 2>&1
if %errorlevel% equ 0 (
    echo [OK] Admin shares (C$, ADMIN$, IPC$) enabled
) else (
    echo [!] Error enabling admin shares
)

REM ============================================================================
REM CONFIGURE WINRM
REM ============================================================================

echo.
echo === CONFIGURING WINRM ===
echo. >> %LOGFILE%
echo === CONFIGURING WINRM === >> %LOGFILE%

echo Executing WinRM quickconfig...
winrm quickconfig -quiet >> %LOGFILE% 2>&1
if %errorlevel% equ 0 (
    echo [OK] WinRM configured
) else (
    echo [!] WinRM configuration attempted
)

REM ============================================================================
REM VERIFICATION
REM ============================================================================

echo.
echo === VERIFICATION ===
echo. >> %LOGFILE%
echo === VERIFICATION === >> %LOGFILE%

echo Checking Service Status:
echo Checking Service Status: >> %LOGFILE%
sc query Winmgmt >> %LOGFILE% 2>&1
sc query RemoteRegistry >> %LOGFILE% 2>&1
sc query WinRM >> %LOGFILE% 2>&1

net start | find /i "WMI"
net start | find /i "RemoteRegistry"
net start | find /i "WinRM"

REM ============================================================================
REM COMPLETION
REM ============================================================================

echo.
echo ============================================================================
echo Configuration Complete
echo ============================================================================
echo.
echo IMPORTANT: A restart is recommended for all changes to take effect.
echo Restart Command: shutdown /r /t 60 /c "Restarting for scan configuration"
echo.
echo Log file saved to: %LOGFILE%
echo.

REM Ask for restart
set /p restart="Restart now? (Y/N): "
if /i "%restart%"=="Y" (
    echo Restarting in 60 seconds...
    shutdown /r /t 60 /c "Restarting for vulnerability scan configuration"
) else (
    echo Please restart manually later for all changes to take effect.
)

echo %date% %time% - Script completed >> %LOGFILE%
pause
