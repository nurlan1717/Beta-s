@echo off
echo ================================================
echo   Adding Windows Firewall Rule for Port 8000
echo ================================================
echo.
echo This script must be run as Administrator!
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script requires Administrator privileges.
    echo Right-click and select "Run as Administrator"
    pause
    exit /b 1
)

echo Adding firewall rule for RANSOMRUN Backend (TCP Port 8000)...
netsh advfirewall firewall add rule name="RANSOMRUN Backend Server" dir=in action=allow protocol=TCP localport=8000

if %errorLevel% equ 0 (
    echo.
    echo SUCCESS: Firewall rule added successfully!
    echo Port 8000 is now accessible from the network.
) else (
    echo.
    echo ERROR: Failed to add firewall rule.
)

echo.
pause
