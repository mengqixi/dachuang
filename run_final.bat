@echo off
cd /d "%~dp0"
echo Starting the canonical application on ports 5000 and 5001...
python app.py
pause
