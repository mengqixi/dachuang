@echo off
cd /d "%~dp0"
echo Starting one canonical Flask process. The same app serves the UI and API.
echo User:  http://127.0.0.1:5000/
echo Admin: http://127.0.0.1:5001/
python app.py
