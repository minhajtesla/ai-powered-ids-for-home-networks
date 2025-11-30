@echo off
title AI-Powered IDS - Dashboard
color 0B

echo ========================================
echo  AI-Powered IDS - Dashboard
echo  Real-time Network Monitor
echo ========================================
echo.

cd /d "D:\github project Network\ai-powered-ids-for-home-networks"

echo Starting dashboard...
echo Dashboard will open in your browser automatically
echo.
echo URL: http://localhost:8501
echo.

"%CD%\venv\Scripts\python.exe" -m streamlit run "dashboard\app.py"

pause
