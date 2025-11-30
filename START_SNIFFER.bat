@echo off
title AI-Powered IDS - Network Sniffer (Administrator Mode)
color 0A

echo ========================================
echo  AI-Powered IDS - Network Sniffer
echo  Administrator Mode Required
echo ========================================
echo.

cd /d "D:\github project Network\ai-powered-ids-for-home-networks"

echo [1/2] Activating virtual environment...
call .venv\Scripts\activate.bat
echo.

echo [2/2] Starting packet sniffer...
echo.
echo IMPORTANT: This will capture ALL traffic on your WiFi network
echo You will see all devices connected to your router!
echo.
pause

python src\sniffer.py

pause
